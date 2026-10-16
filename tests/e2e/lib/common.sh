#!/usr/bin/env bash
# Shared helpers for the end-to-end tests. Source this file; do not run it.
#
# The tests run the app image against a real Wazuh manager (the official
# wazuh/wazuh-manager image), so what they prove is what a user gets: the agent
# enrolls, stays connected, keeps its identity, and its data reaches the manager.
#
# Style: every function names its arguments and ends with an explicit `return`
# (a bare `return` passes on the status of the last command), which is what the
# SonarQube shell rules ask for.

E2E_ID="${E2E_ID:-$$}"
E2E_NET="e2e-net-${E2E_ID}"
MANAGER_VERSION="${MANAGER_VERSION:-4.14.9}"
MANAGER="e2e-manager-${E2E_ID}"
IMAGE="${IMAGE:-ha-wazuh-agent:test}"

E2E_CONTAINERS=()
E2E_VOLUMES=()
PASSED=0
FAILED=0

log() {
    printf '\n\033[1m==> %s\033[0m\n' "$*"
    return 0
}
info() {
    printf '    %s\n' "$*"
    return 0
}
pass() {
    PASSED=$((PASSED + 1))
    printf '    \033[32mPASS\033[0m %s\n' "$*"
    return 0
}
fail() {
    FAILED=$((FAILED + 1))
    printf '    \033[31mFAIL\033[0m %s\n' "$*"
    return 0
}

track_container() {
    local name="$1"
    E2E_CONTAINERS+=("${name}")
    return 0
}
track_volume() {
    local name="$1"
    E2E_VOLUMES+=("${name}")
    return 0
}

cleanup() {
    local c v
    for c in "${E2E_CONTAINERS[@]}"; do docker rm -f "${c}" > /dev/null 2>&1 || true; done
    for v in "${E2E_VOLUMES[@]}"; do docker volume rm -f "${v}" > /dev/null 2>&1 || true; done
    docker network rm "${E2E_NET}" > /dev/null 2>&1 || true
    return 0
}

# release_since FIRST_CONTAINER FIRST_VOLUME
# Removes what a scenario created (everything tracked from those positions on), so only the manager
# and the scenario that is running use the machine. Called after each scenario, not just at the end.
release_since() {
    local first_c="$1" first_v="$2" i
    local count_c=$((${#E2E_CONTAINERS[@]} - first_c)) count_v=$((${#E2E_VOLUMES[@]} - first_v))
    for ((i = first_c; i < ${#E2E_CONTAINERS[@]}; i++)); do
        docker rm -f "${E2E_CONTAINERS[i]}" > /dev/null 2>&1 || true
    done
    for ((i = first_v; i < ${#E2E_VOLUMES[@]}; i++)); do
        docker volume rm -f "${E2E_VOLUMES[i]}" > /dev/null 2>&1 || true
    done
    info "removed the scenario's ${count_c} containers and ${count_v} volumes"
    return 0
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

# assert DESCRIPTION COMMAND...
assert() {
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then pass "${desc}"; else fail "${desc}"; fi
    return 0
}

# ---- Wazuh manager ---------------------------------------------------------

manager_ports_listening() {
    # 1514 (remoted) and 1515 (authd) listening: 0x05EA / 0x05EB in /proc/net/tcp.
    docker exec "${MANAGER}" bash -c "grep -qi ':05EA ' /proc/net/tcp && grep -qi ':05EB ' /proc/net/tcp"
    return
}

manager_start() {
    docker network create "${E2E_NET}" > /dev/null 2>&1 || true
    docker run -d --name "${MANAGER}" --hostname "${MANAGER}" --network "${E2E_NET}" \
        "wazuh/wazuh-manager:${MANAGER_VERSION}" > /dev/null
    track_container "${MANAGER}"
    wait_for 180 "manager listening on 1514 and 1515" manager_ports_listening
    # Keep every event, not only the ones that match a rule, so tests can see them.
    docker exec "${MANAGER}" bash -c "
        sed -i 's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' /var/ossec/etc/ossec.conf
        /var/ossec/bin/wazuh-control restart > /dev/null 2>&1"
    wait_for 120 "manager restarted" manager_ports_listening
    return
}

# manager_agent_line NAME -> the agent_control line for that agent
manager_agent_line() {
    local name="$1"
    docker exec "${MANAGER}" /var/ossec/bin/agent_control -l 2> /dev/null | grep "Name: ${name}," || true
    return 0
}

manager_agent_active() {
    local name="$1" line
    line="$(manager_agent_line "${name}")"
    [[ "${line}" == *Active* ]]
    return
}

manager_agent_id() {
    local name="$1"
    manager_agent_line "${name}" | sed -n 's/.*ID: \([0-9]*\),.*/\1/p'
    return 0
}

manager_agent_count() {
    docker exec "${MANAGER}" /var/ossec/bin/agent_control -l 2> /dev/null | grep -c 'ID: 0[0-9]*, Name: ' || true
    return 0
}

# manager_archive_count FIXED-STRING -> number of archived events containing it
manager_archive_count() {
    local text="$1"
    docker exec "${MANAGER}" bash -c "grep -cF -- '${text}' /var/ossec/logs/archives/archives.json 2> /dev/null || true"
    return 0
}

# manager_alert_count FIXED-STRING
manager_alert_count() {
    local text="$1"
    docker exec "${MANAGER}" bash -c "grep -cF -- '${text}' /var/ossec/logs/alerts/alerts.json 2> /dev/null || true"
    return 0
}

# Predicates for wait_for (it runs a command, so these are plain functions).
manager_has_archive() {
    local text="$1"
    [[ "$(manager_archive_count "${text}")" -ge 1 ]]
    return
}

manager_has_alert_path() {
    local path="$1"
    [[ "$(manager_alert_count "\"path\":\"${path}\"")" -ge 1 ]]
    return
}

# manager_has_alert_rule FIXED-STRING RULE-ID: an alert mentioning the string, raised by that rule
manager_has_alert_rule() {
    local text="$1" rule="$2"
    docker exec "${MANAGER}" bash -c \
        "grep -F -- '${text}' /var/ossec/logs/alerts/alerts.json | grep -qF '\"id\":\"${rule}\"'"
    return
}

container_healthy() {
    local name="$1"
    [[ "$(docker inspect -f '{{.State.Health.Status}}' "${name}" 2> /dev/null)" == healthy ]]
    return
}

# The log is captured before it is searched. Piping `docker logs` into `grep -q` under
# pipefail turns a successful match into a failure: grep exits at the first match, docker
# gets SIGPIPE, and the pipeline reports 141. That would also make "must NOT contain" checks
# pass for the wrong reason.
container_log_has() {
    local name="$1" text="$2" logs
    logs="$(docker logs "${name}" 2>&1)"
    grep -qF -- "${text}" <<< "${logs}"
    return
}

# container_log_matches CONTAINER EXTENDED-REGEX (case-insensitive)
container_log_matches() {
    local name="$1" pattern="$2" logs
    logs="$(docker logs "${name}" 2>&1)"
    grep -qiE -- "${pattern}" <<< "${logs}"
    return
}

# ---- The app under test ----------------------------------------------------

# write_options VOLUME JSON   puts /data/options.json into the app's data volume
#
# The app monitors the Home Assistant OS host unless told otherwise, which needs the host's process
# namespace (see host_agent_start). Most scenarios test the agent itself in a plain container, so
# "monitor_host" is false unless the options say otherwise.
write_options() {
    local volume="$1" json="$2"
    docker volume create "${volume}" > /dev/null
    track_volume "${volume}"
    printf '%s' "${json}" | jq -c '{monitor_host: false} + .' | docker run --rm -i -v "${volume}:/data" --entrypoint bash "${IMAGE}" \
        -c 'cat > /data/options.json'
    return
}

# agent_start NAME VOLUME [extra docker run args...]
agent_start() {
    local name="$1" volume="$2"
    shift 2
    docker rm -f "${name}" > /dev/null 2>&1 || true
    # --init: Home Assistant starts an app under Docker's init unless the app opts out.
    docker run -d --init --name "${name}" --network "${E2E_NET}" -v "${volume}:/data" "$@" "${IMAGE}" > /dev/null
    track_container "${name}"
    return 0
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
    return 0
}

agent_log() {
    local name="$1"
    docker logs "${name}" 2>&1
    return
}

# dump_agent NAME  (diagnostics on failure)
dump_agent() {
    local name="$1"
    info "---- last 40 lines of ${name} ----"
    docker logs --tail 40 "${name}" 2>&1 | sed 's/^/    | /'
    return 0
}

# ---- The status page ---------------------------------------------------------

# ui_get HOST PATH [curl options...] -> the response body. The request comes from a helper
# container on the test network, like a client other than the Supervisor would.
ui_get() {
    local host="$1" path="$2"
    shift 2
    docker run --rm --network "${E2E_NET}" --entrypoint curl "${IMAGE}" -sS -m 10 "$@" "http://${host}:8099${path}"
    return
}

# ui_code HOST PATH [curl options...] -> the HTTP status code
ui_code() {
    local host="$1" path="$2"
    shift 2
    docker run --rm --network "${E2E_NET}" --entrypoint curl "${IMAGE}" -sS -m 10 -o /dev/null -w '%{http_code}' "$@" "http://${host}:8099${path}"
    return
}

# ui_json HOST PATH JQ-FILTER
ui_json() {
    local host="$1" path="$2" filter="$3"
    ui_get "${host}" "${path}" | jq -r "${filter}"
    return
}

# ui_state_is HOST STATE... : the page reports one of the given states (a predicate for wait_for)
ui_state_is() {
    local host="$1" state current
    shift
    current="$(ui_json "${host}" /api/status .state 2> /dev/null)"
    for state in "$@"; do
        [[ "${current}" == "${state}" ]] && return 0
    done
    return 1
}

summary() {
    printf '\n\033[1m%s passed, %s failed\033[0m\n' "${PASSED}" "${FAILED}"
    [[ "${FAILED}" -eq 0 ]]
    return
}
