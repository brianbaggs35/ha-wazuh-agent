#!/usr/bin/env bash
# Shared helpers for the end-to-end tests. Source this file; do not run it.
#
# The tests run the app image against a real Wazuh manager (the official
# wazuh/wazuh-manager image), so what they prove is what a user gets: the agent
# enrolls, stays connected, keeps its identity, and its data reaches the manager.

E2E_ID="${E2E_ID:-$$}"
E2E_NET="e2e-net-${E2E_ID}"
MANAGER_VERSION="${MANAGER_VERSION:-4.14.9}"
MANAGER="e2e-manager-${E2E_ID}"
IMAGE="${IMAGE:-ha-wazuh-agent:test}"

E2E_CONTAINERS=()
E2E_VOLUMES=()
PASSED=0
FAILED=0

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
pass() { PASSED=$((PASSED + 1)); printf '    \033[32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$((FAILED + 1)); printf '    \033[31mFAIL\033[0m %s\n' "$*"; }

track_container() { E2E_CONTAINERS+=("$1"); }
track_volume() { E2E_VOLUMES+=("$1"); }

cleanup() {
    local c v
    for c in "${E2E_CONTAINERS[@]}"; do docker rm -f "${c}" > /dev/null 2>&1 || true; done
    for v in "${E2E_VOLUMES[@]}"; do docker volume rm -f "${v}" > /dev/null 2>&1 || true; done
    docker network rm "${E2E_NET}" > /dev/null 2>&1 || true
}

# wait_for SECONDS DESCRIPTION COMMAND...   (polls every 2s)
wait_for() {
    local timeout="$1" desc="$2"
    shift 2
    local waited=0
    until "$@" > /dev/null 2>&1; do
        if [[ "${waited}" -ge "${timeout}" ]]; then
            info "timed out after ${timeout}s waiting for: ${desc}"
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 0
}

assert() { # assert DESCRIPTION COMMAND...
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then pass "${desc}"; else fail "${desc}"; fi
}

# ---- Wazuh manager ---------------------------------------------------------

manager_start() {
    docker network create "${E2E_NET}" > /dev/null 2>&1 || true
    docker run -d --name "${MANAGER}" --hostname "${MANAGER}" --network "${E2E_NET}" \
        "wazuh/wazuh-manager:${MANAGER_VERSION}" > /dev/null
    track_container "${MANAGER}"
    # 1514 (remoted) and 1515 (authd) listening: 0x05EA / 0x05EB in /proc/net/tcp.
    wait_for 180 "manager listening on 1514 and 1515" docker exec "${MANAGER}" bash -c \
        "grep -qi ':05EA ' /proc/net/tcp && grep -qi ':05EB ' /proc/net/tcp"
    # Keep every event, not only the ones that match a rule, so tests can see them.
    docker exec "${MANAGER}" bash -c "
        sed -i 's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' /var/ossec/etc/ossec.conf
        /var/ossec/bin/wazuh-control restart > /dev/null 2>&1"
    wait_for 120 "manager restarted" docker exec "${MANAGER}" bash -c \
        "grep -qi ':05EA ' /proc/net/tcp && grep -qi ':05EB ' /proc/net/tcp"
}

manager_agent_line() { # NAME -> the agent_control line for that agent
    docker exec "${MANAGER}" /var/ossec/bin/agent_control -l 2> /dev/null | grep "Name: $1," || true
}
manager_agent_active() { manager_agent_line "$1" | grep -q 'Active'; }
manager_agent_id() { manager_agent_line "$1" | sed -n 's/.*ID: \([0-9]*\),.*/\1/p'; }
manager_agent_count() { docker exec "${MANAGER}" /var/ossec/bin/agent_control -l 2> /dev/null | grep -c 'ID: 0[0-9]*, Name: ' || true; }

manager_archive_count() { # FIXED-STRING -> number of archived events containing it
    docker exec "${MANAGER}" bash -c "grep -cF -- '$1' /var/ossec/logs/archives/archives.json 2> /dev/null || true"
}
manager_alert_count() { # FIXED-STRING
    docker exec "${MANAGER}" bash -c "grep -cF -- '$1' /var/ossec/logs/alerts/alerts.json 2> /dev/null || true"
}

# Predicates for wait_for (it runs a command, so these are plain functions).
manager_has_archive() { [[ "$(manager_archive_count "$1")" -ge 1 ]]; }
manager_has_alert_path() { [[ "$(manager_alert_count "\"path\":\"$1\"")" -ge 1 ]]; }
manager_has_alert_rule() { # FIXED-STRING RULE-ID: an alert mentioning the string, raised by that rule
    docker exec "${MANAGER}" bash -c \
        "grep -F -- '$1' /var/ossec/logs/alerts/alerts.json | grep -qF '\"id\":\"$2\"'"
}
container_healthy() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$1" 2> /dev/null)" == healthy ]]; }
# The log is captured before it is searched. Piping `docker logs` into `grep -q` under
# pipefail turns a successful match into a failure: grep exits at the first match, docker
# gets SIGPIPE, and the pipeline reports 141. That would also make "must NOT contain" checks
# pass for the wrong reason.
container_log_has() {
    local logs
    logs="$(docker logs "$1" 2>&1)"
    grep -qF -- "$2" <<< "${logs}"
}
container_log_matches() { # CONTAINER EXTENDED-REGEX (case-insensitive)
    local logs
    logs="$(docker logs "$1" 2>&1)"
    grep -qiE -- "$2" <<< "${logs}"
}

# ---- The app under test ----------------------------------------------------

# write_options VOLUME JSON   puts /data/options.json into the app's data volume
write_options() {
    docker volume create "$1" > /dev/null
    track_volume "$1"
    printf '%s' "$2" | docker run --rm -i -v "$1:/data" --entrypoint bash "${IMAGE}" \
        -c 'cat > /data/options.json'
}

# agent_start NAME VOLUME [extra docker run args...]
agent_start() {
    local name="$1" volume="$2"
    shift 2
    docker rm -f "${name}" > /dev/null 2>&1 || true
    docker run -d --name "${name}" --network "${E2E_NET}" -v "${volume}:/data" "$@" "${IMAGE}" > /dev/null
    track_container "${name}"
}

# agent_settle CONTAINER
# The first time an agent connects, the manager sends it the group configuration and the
# agent restarts its own daemons (auto_restart). Events produced during that restart are
# not delivered, so tests that inject events wait until it is over.
agent_settle() {
    local c="$1"
    wait_for 90 "first-connection configuration reload" container_log_has "${c}" \
        "Agent is reloading due to shared configuration changes" || info "no configuration reload seen"
    sleep 12
    wait_for 120 "agent connected again after the reload" docker exec "${c}" wazuh-ha-healthcheck
    sleep 5
}

agent_log() { docker logs "$1" 2>&1; }
agent_exec() { local c="$1"; shift; docker exec "${c}" "$@"; }

dump_agent() { # NAME  (diagnostics on failure)
    info "---- last 40 lines of $1 ----"
    docker logs --tail 40 "$1" 2>&1 | sed 's/^/    | /'
}

summary() {
    printf '\n\033[1m%s passed, %s failed\033[0m\n' "${PASSED}" "${FAILED}"
    [[ "${FAILED}" -eq 0 ]]
}
