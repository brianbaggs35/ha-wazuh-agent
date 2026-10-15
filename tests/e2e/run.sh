#!/usr/bin/env bash
# End-to-end tests: the app image against a real Wazuh manager.
#
#   IMAGE=ha-wazuh-agent:test tests/e2e/run.sh [scenario ...]
#
# Scenarios: validation enroll journal fim config upgrade duplicate reenroll password   (default: all)
# Environment: IMAGE (image under test), MANAGER_VERSION (default 4.14.9),
#              E2E_KEEP=1 to leave containers behind for debugging.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${HERE}/lib/common.sh"
# shellcheck source=lib/journal.sh
source "${HERE}/lib/journal.sh"

[[ -n "${E2E_KEEP:-}" ]] || trap cleanup EXIT

JOURNAL_MID="a1b2c3d4e5f60718293a4b5c6d7e8f90"
FAST='"enrollment_delay": 1'   # do not wait the default 20s after enrolling

# ---------------------------------------------------------------------------
scenario_enroll() {
    log "enroll: a manager address is all it takes, and the identity survives restarts"
    local vol="e2e-enroll-data-${E2E_ID}" c="e2e-enroll-${E2E_ID}" name="e2e-enroll"
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c}" "${vol}"

    if wait_for 150 "agent active at the manager" manager_agent_active "${name}"; then
        pass "agent enrolled and is Active at the manager"
    else
        fail "agent enrolled and is Active at the manager"
        dump_agent "${c}"
        return
    fi
    local id before want_version
    id="$(manager_agent_id "${name}")"
    before="$(manager_agent_count)"
    want_version="$(docker image inspect "${IMAGE}" --format '{{ index .Config.Labels "com.wazuh.agent.version" }}')"

    assert "manager reports the agent version ${want_version}" bash -c \
        "docker exec ${MANAGER} /var/ossec/bin/agent_control -i ${id} | grep -q 'Client version:.*v${want_version}'"
    assert "container becomes healthy (agent connected)" wait_for 150 "healthy" container_healthy "${c}"
    assert "all agent daemons are running" bash -c \
        "out=\$(docker exec ${c} /var/ossec/bin/wazuh-control status); for d in agentd execd logcollector modulesd syscheckd; do grep -q \"wazuh-\$d is running\" <<< \"\$out\" || exit 1; done"
    assert "/var/ossec lives on the persistent volume" bash -c \
        "[[ \"\$(docker exec ${c} readlink /var/ossec)\" == /data/ossec ]]"
    assert "enrollment secrets are not world readable" bash -c \
        "[[ \"\$(docker exec ${c} stat -c %a /data/ossec/etc/client.keys)\" =~ ^6[0-4]0$ ]]"

    info "restarting the container (same data)"
    docker restart "${c}" > /dev/null
    assert "agent reconnects after a restart" wait_for 150 "reconnected" docker exec "${c}" wazuh-ha-healthcheck
    [[ "$(manager_agent_id "${name}")" == "${id}" ]] \
        && pass "restart kept the same agent ID (${id})" || fail "agent ID changed after a restart"

    info "recreating the container on the same volume (what an app update does)"
    agent_start "${c}" "${vol}"
    assert "agent reconnects after the container is recreated" wait_for 150 "reconnected" docker exec "${c}" wazuh-ha-healthcheck
    [[ "$(manager_agent_id "${name}")" == "${id}" ]] && pass "recreate kept the same agent ID" || fail "agent ID changed after recreate"
    [[ "$(manager_agent_count)" == "${before}" ]] && pass "no duplicate agent was registered" || fail "a duplicate agent was registered"
    if container_log_has "${c}" 'Valid key received'; then
        fail "the agent enrolled again instead of reusing its key"
    else
        pass "the agent reused its saved key (no new enrollment)"
    fi
}

# ---------------------------------------------------------------------------
scenario_journal() {
    log "journal: the host journal is read, filtered, and raises alerts"
    local vol="e2e-journal-data-${E2E_ID}" jvol="e2e-journal-vol-${E2E_ID}" jw="e2e-jw-${E2E_ID}"
    local c="e2e-journal-${E2E_ID}" name="e2e-journal"
    track_volume "${jvol}"
    track_container "${jw}"
    journal_writer_start "${jw}" "${jvol}" "${JOURNAL_MID}" || { fail "journal writer started"; return; }
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c}" "${vol}" -v "${jvol}:/var/log/journal:ro"

    wait_for 150 "agent active" manager_agent_active "${name}" || { fail "agent active"; dump_agent "${c}"; return; }
    agent_settle "${c}"
    if wait_for 90 "journal monitoring" container_log_has "${c}" "Monitoring journal entries"; then
        pass "logcollector is monitoring the journal"
    else
        fail "logcollector is monitoring the journal"
        dump_agent "${c}"
        return
    fi
    [[ "$(docker exec "${c}" cat /etc/machine-id)" == "${JOURNAL_MID}" ]] \
        && pass "the container adopted the host journal's machine ID" \
        || fail "the container adopted the host journal's machine ID"

    # Should arrive.
    journal_emit "${jw}" sshd 5 "Failed password for invalid user e2eauth from 192.0.2.21 port 4001 ssh2"
    journal_emit "${jw}" homeassistant 4 "Login attempt or request with invalid authentication from 192.0.2.22 (192.0.2.22). e2e-core-marker"
    journal_emit "${jw}" hassio_supervisor 4 "e2e-supervisor-marker"
    journal_emit "${jw}" cron 3 "e2e-error-marker"
    JOURNAL_TRANSPORT=kernel journal_emit "${jw}" kernel 4 "e2e-kernel-marker"
    # Must not arrive: not a selected source and not an error.
    journal_emit "${jw}" cron 6 "e2e-noise-marker"
    journal_emit "${jw}" addon_core_ssh 6 "e2e-app-marker"
    journal_emit "${jw}" sshd 5 "Failed password for invalid user e2elast from 192.0.2.23 port 4002 ssh2"

    local marker
    for marker in 192.0.2.21 e2e-core-marker e2e-supervisor-marker e2e-error-marker e2e-kernel-marker 192.0.2.23; do
        if wait_for 90 "event ${marker}" manager_has_archive "${marker}"; then
            pass "journal event reached the manager: ${marker}"
        else
            fail "journal event reached the manager: ${marker}"
        fi
    done
    # The last wanted event arrived, so anything that was going to be (wrongly) sent has been.
    [[ "$(manager_archive_count e2e-noise-marker)" == 0 ]] && pass "unselected journal noise was filtered out" || fail "unselected journal noise was filtered out"
    [[ "$(manager_archive_count e2e-app-marker)" == 0 ]] && pass "app logs are off by default (journal_apps=false)" || fail "app logs are off by default (journal_apps=false)"

    if wait_for 60 "sshd alert" manager_has_alert_rule 192.0.2.21 5710; then
        pass "the SSH failure raised Wazuh rule 5710"
    else
        fail "the SSH failure raised Wazuh rule 5710"
    fi
}

# ---------------------------------------------------------------------------
scenario_fim() {
    log "fim: Home Assistant configuration changes are detected, noise is not"
    local vol="e2e-fim-data-${E2E_ID}" cfg="e2e-fim-config-${E2E_ID}" c="e2e-fim-${E2E_ID}" name="e2e-fim"
    track_volume "${cfg}"
    docker volume create "${cfg}" > /dev/null
    docker run --rm -v "${cfg}:/h" --entrypoint bash "${IMAGE}" -c \
        'echo "homeassistant:" > /h/configuration.yaml; echo "api_key: token-before-9f3a7c1e" > /h/secrets.yaml; mkdir -p /h/custom_components'
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c}" "${vol}" -v "${cfg}:/homeassistant:ro"

    wait_for 150 "agent active" manager_agent_active "${name}" || { fail "agent active"; dump_agent "${c}"; return; }
    agent_settle "${c}"
    wait_for 90 "realtime FIM" container_log_has "${c}" "Real-time file integrity monitoring started" \
        && pass "real-time file integrity monitoring started" || { fail "real-time file integrity monitoring started"; dump_agent "${c}"; return; }
    sleep 5

    local w=(docker run --rm -v "${cfg}:/h" --entrypoint bash "${IMAGE}" -c)
    "${w[@]}" 'echo "automation: []" >> /h/configuration.yaml'
    "${w[@]}" 'echo "print(1)" > /h/custom_components/evil.py'
    "${w[@]}" 'echo "api_key: token-after-9f3a7c1e" > /h/secrets.yaml'
    # Noise that the default ignore list must swallow.
    "${w[@]}" 'echo noise >> /h/home-assistant.log; echo noise > /h/home-assistant_v2.db; echo noise > /h/.storage_probe.db-wal'

    local path
    for path in /homeassistant/configuration.yaml /homeassistant/custom_components/evil.py /homeassistant/secrets.yaml; do
        if wait_for 90 "FIM alert ${path}" manager_has_alert_path "${path}"; then
            pass "FIM alert for ${path}"
        else
            fail "FIM alert for ${path}"
        fi
    done
    sleep 10
    [[ "$(manager_archive_count '/homeassistant/home-assistant_v2.db')" == 0 ]] \
        && pass "the recorder database is ignored" || fail "the recorder database is ignored"
    [[ "$(manager_archive_count '/homeassistant/home-assistant.log')" == 0 ]] \
        && pass "the log file is ignored" || fail "the log file is ignored"
    # secrets.yaml changed, but its content must never be sent.
    if docker exec "${MANAGER}" bash -c "grep -F '/homeassistant/secrets.yaml' /var/ossec/logs/alerts/alerts.json | grep -qE 'token-(before|after)-9f3a7c1e'"; then
        fail "secrets.yaml content is not sent to the manager"
    else
        pass "secrets.yaml content is not sent to the manager"
    fi
}

# ---------------------------------------------------------------------------
scenario_config() {
    log "config: groups, labels, failover addresses and extra configuration are applied"
    docker exec "${MANAGER}" /var/ossec/bin/agent_groups -a -g e2e-group -q > /dev/null 2>&1 || true
    local vol="e2e-config-data-${E2E_ID}" extra="e2e-config-extra-${E2E_ID}" c="e2e-config-${E2E_ID}" name="e2e-config"
    track_volume "${extra}"
    docker volume create "${extra}" > /dev/null
    docker run --rm -v "${extra}:/c" --entrypoint bash "${IMAGE}" -c \
        'cat > /c/ossec_extra.conf <<EOF
<ossec_config>
  <labels>
    <label key="e2e_extra">from-extra-file</label>
  </labels>
</ossec_config>
EOF'
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"manager_failover_addresses\": [\"${MANAGER}\"],
        \"agent_name\": \"${name}\", \"agent_groups\": [\"e2e-group\"], \"auto_labels\": false,
        \"agent_labels\": [{\"key\": \"e2e_label\", \"value\": \"hello\"}],
        \"log_files\": [{\"path\": \"/logs/e2e-labels.log\", \"format\": \"syslog\"}], ${FAST}}"
    # The monitored file lives on its own volume so it exists before the agent starts.
    local logvol="e2e-config-logs-${E2E_ID}"
    track_volume "${logvol}"
    docker volume create "${logvol}" > /dev/null
    docker run --rm -v "${logvol}:/l" --entrypoint bash "${IMAGE}" -c 'touch /l/e2e-labels.log'
    agent_start "${c}" "${vol}" -v "${extra}:/config:ro" -v "${logvol}:/logs"

    wait_for 150 "agent active" manager_agent_active "${name}" || { fail "agent active"; dump_agent "${c}"; return; }
    agent_settle "${c}"
    local id
    id="$(manager_agent_id "${name}")"
    docker exec "${MANAGER}" /var/ossec/bin/agent_groups -l -g e2e-group 2> /dev/null | grep -q "${id}" \
        && pass "the agent joined the requested group" || fail "the agent joined the requested group"
    docker exec "${c}" grep -q 'e2e_extra' /var/ossec/etc/ossec.conf \
        && pass "ossec_extra.conf was appended to the configuration" || fail "ossec_extra.conf was appended to the configuration"
    docker exec "${c}" grep -c '<server>' /var/ossec/etc/ossec.conf | grep -qx 2 \
        && pass "the failover manager became a second <server>" || fail "the failover manager became a second <server>"

    # A custom log file via log_files; events the agent sends carry its labels.
    wait_for 60 "log file picked up" container_log_has "${c}" "Analyzing file: '/logs/e2e-labels.log'" \
        && pass "log_files entry is being monitored" || fail "log_files entry is being monitored"
    docker run --rm -v "${logvol}:/l" --entrypoint bash "${IMAGE}" -c \
        'echo "Oct 15 10:00:00 homeassistant e2eprobe: e2e-label-probe" >> /l/e2e-labels.log'
    if wait_for 90 "custom log event" manager_has_archive "e2e-label-probe"; then
        pass "a custom log file event reached the manager"
        docker exec "${MANAGER}" bash -c "grep -F e2e-label-probe /var/ossec/logs/archives/archives.json | head -1" \
            | grep -q '"e2e_label":"hello"' \
            && pass "the event carries the agent label from agent_labels" || fail "the event carries the agent label from agent_labels"
    else
        fail "a custom log file event reached the manager"
    fi
}

# ---------------------------------------------------------------------------
scenario_validation() {
    log "validation: bad configuration fails fast with a message that names the option"
    local case_name json expected vol out rc
    while IFS='|' read -r case_name json expected; do
        vol="e2e-val-${case_name}-${E2E_ID}"
        write_options "${vol}" "${json}"
        out="$(timeout 120 docker run --rm -v "${vol}:/data" "${IMAGE}" 2>&1)"
        rc=$?
        if [[ "${rc}" -ne 0 ]] && grep -qF -- "${expected}" <<< "${out}"; then
            pass "${case_name}: refused to start with \"${expected}\""
        else
            fail "${case_name}: expected a failure mentioning \"${expected}\" (exit ${rc})"
            printf '%s\n' "${out}" | tail -8 | sed 's/^/    | /'
        fi
    done << 'CASES'
no_manager|{}|manager_address: required
bad_manager|{"manager_address": "a b"}|must be a single host name
lt_in_value|{"manager_address": "m", "fim_ignore": ["a<b"]}|the character "<" is not supported
short_name|{"manager_address": "m", "agent_name": "a"}|agent_name: at least 2 characters
bad_label|{"manager_address": "m", "agent_labels": [{"key": "bad key", "value": "x"}]}|agent_labels[0].key
cert_without_key|{"manager_address": "m", "enrollment_certificate_path": "/x"}|must be set together
bad_interval|{"manager_address": "m", "sca_interval": "soon"}|sca_interval
CASES
}

# ---------------------------------------------------------------------------
scenario_upgrade() {
    log "upgrade: a new app release refreshes the agent program files but keeps the identity"
    local vol="e2e-upgrade-data-${E2E_ID}" c="e2e-upgrade-${E2E_ID}" name="e2e-upgrade"
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c}" "${vol}"
    wait_for 150 "agent active" manager_agent_active "${name}" || { fail "agent active"; dump_agent "${c}"; return; }
    local id keys_before
    id="$(manager_agent_id "${name}")"
    docker stop "${c}" > /dev/null
    # Pretend the volume holds files from an older release: old version marker, a
    # stale program file, and a corrupted program binary that an update must replace.
    docker run --rm -v "${vol}:/data" --entrypoint bash "${IMAGE}" -c '
        jq ".version = \"4.0.0\"" /data/ossec/VERSION.json > /tmp/version.json
        cat /tmp/version.json > /data/ossec/VERSION.json
        echo stale > /data/ossec/bin/removed-in-new-release
        echo corrupt > /data/ossec/active-response/bin/firewall-drop
        sha256sum /data/ossec/etc/client.keys | cut -d" " -f1 > /data/keys.sha'
    keys_before="$(docker run --rm -v "${vol}:/data" --entrypoint cat "${IMAGE}" /data/keys.sha)"
    agent_start "${c}" "${vol}"
    wait_for 150 "agent reconnects" docker exec "${c}" wazuh-ha-healthcheck \
        && pass "agent reconnects after the simulated update" || { fail "agent reconnects after the simulated update"; dump_agent "${c}"; return; }
    container_log_has "${c}" 'Updating the Wazuh agent program files' \
        && pass "the update path ran" || fail "the update path ran"
    docker exec "${c}" test ! -e /var/ossec/bin/removed-in-new-release \
        && pass "stale program files were removed" || fail "stale program files were removed"
    docker exec "${c}" grep -q corrupt /var/ossec/active-response/bin/firewall-drop \
        && fail "a damaged program file was restored from the image" || pass "a damaged program file was restored from the image"
    [[ "$(docker exec "${c}" jq -r .version /var/ossec/VERSION.json)" == "$(docker image inspect "${IMAGE}" --format '{{ index .Config.Labels "com.wazuh.agent.version" }}')" ]] \
        && pass "the version marker was refreshed" || fail "the version marker was refreshed"
    [[ "$(docker exec "${c}" sha256sum /data/ossec/etc/client.keys | cut -d' ' -f1)" == "${keys_before}" ]] \
        && pass "the agent key was not touched" || fail "the agent key was not touched"
    [[ "$(manager_agent_id "${name}")" == "${id}" ]] \
        && pass "the agent kept its manager-side identity" || fail "the agent kept its manager-side identity"
}

# ---------------------------------------------------------------------------
scenario_duplicate() {
    log "duplicate: a second agent with the same name is refused and the first is unaffected"
    local v1="e2e-dup1-data-${E2E_ID}" v2="e2e-dup2-data-${E2E_ID}" c1="e2e-dup1-${E2E_ID}" c2="e2e-dup2-${E2E_ID}" name="e2e-dup"
    write_options "${v1}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c1}" "${v1}"
    wait_for 150 "first agent active" manager_agent_active "${name}" || { fail "first agent active"; dump_agent "${c1}"; return; }
    local before
    before="$(manager_agent_count)"
    write_options "${v2}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c2}" "${v2}"
    sleep 30
    [[ "$(manager_agent_count)" == "${before}" ]] \
        && pass "the duplicate name did not create a second agent" || fail "the duplicate name did not create a second agent"
    info "what the second agent logs:"
    agent_log "${c2}" | sed 's/\x1b\[[0-9;]*m//g' | grep -iE "duplicate|already|ERROR" | head -3 | sed 's/^/    | /'
    container_log_matches "${c2}" "duplicate|already" \
        && pass "the log explains that the name is already in use" || fail "the log explains that the name is already in use"
    manager_agent_active "${name}" && pass "the original agent is unaffected" || fail "the original agent is unaffected"
}

# ---------------------------------------------------------------------------
scenario_reenroll() {
    log "reenroll: force_reenroll replaces a key the manager no longer knows"
    local vol="e2e-reenroll-data-${E2E_ID}" c="e2e-reenroll-${E2E_ID}" name="e2e-reenroll"
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c}" "${vol}"
    wait_for 150 "agent active" manager_agent_active "${name}" || { fail "agent active"; dump_agent "${c}"; return; }
    local id
    id="$(manager_agent_id "${name}")"
    docker stop "${c}" > /dev/null
    docker exec "${MANAGER}" /var/ossec/bin/manage_agents -r "${id}" > /dev/null 2>&1
    [[ -z "$(manager_agent_line "${name}")" ]] && pass "the agent was removed on the manager" || fail "the agent was removed on the manager"

    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", \"force_reenroll\": true, ${FAST}}"
    agent_start "${c}" "${vol}"
    if wait_for 150 "agent active again" manager_agent_active "${name}"; then
        pass "force_reenroll registered the agent again"
    else
        fail "force_reenroll registered the agent again"
        dump_agent "${c}"
    fi
    container_log_has "${c}" 'force_reenroll is on' \
        && pass "the app warns that force_reenroll is on" || fail "the app warns that force_reenroll is on"
}

# ---------------------------------------------------------------------------
scenario_password() {
    log "password: enrollment with a registration password"
    docker exec "${MANAGER}" bash -c '
        printf "%s" "e2e-secret-pw" > /var/ossec/etc/authd.pass
        chown root:wazuh /var/ossec/etc/authd.pass; chmod 640 /var/ossec/etc/authd.pass
        sed -i "s#<use_password>no</use_password>#<use_password>yes</use_password>#" /var/ossec/etc/ossec.conf
        grep -c "<use_password>yes</use_password>" /var/ossec/etc/ossec.conf
        /var/ossec/bin/wazuh-control restart > /dev/null 2>&1' | grep -qx 1 || { fail "manager configured to require a password"; return; }
    wait_for 120 "manager back" docker exec "${MANAGER}" bash -c "grep -qi ':05EB ' /proc/net/tcp"

    local bad="e2e-badpw-${E2E_ID}" good="e2e-goodpw-${E2E_ID}"
    write_options "${bad}-d" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"e2e-badpw\", \"enrollment_password\": \"nope\", ${FAST}}"
    agent_start "${bad}" "${bad}-d"
    write_options "${good}-d" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"e2e-goodpw\", \"enrollment_password\": \"e2e-secret-pw\", ${FAST}}"
    agent_start "${good}" "${good}-d"

    if wait_for 150 "good password agent active" manager_agent_active e2e-goodpw; then
        pass "the right registration password enrolls the agent"
    else
        fail "the right registration password enrolls the agent"
        dump_agent "${good}"
    fi
    [[ -z "$(manager_agent_line e2e-badpw)" ]] \
        && pass "a wrong registration password is refused" || fail "a wrong registration password is refused"
    [[ "$(docker exec "${good}" stat -c '%U:%G %a' /data/ossec/etc/authd.pass)" == "root:wazuh 640" ]] \
        && pass "authd.pass is root:wazuh 0640" || fail "authd.pass is root:wazuh 0640"
    docker exec "${good}" grep -q 'e2e-secret-pw' /data/ossec/etc/ossec.conf \
        && fail "the password is not written into ossec.conf" || pass "the password is not written into ossec.conf"
    container_log_has "${good}" 'e2e-secret-pw' \
        && fail "the password never appears in the log" || pass "the password never appears in the log"
}

# ---------------------------------------------------------------------------
main() {
    local scenarios=("$@")
    [[ ${#scenarios[@]} -gt 0 ]] || scenarios=(validation enroll journal fim config upgrade duplicate reenroll password)

    log "image under test: ${IMAGE}   manager: wazuh-manager ${MANAGER_VERSION}"
    # Validation needs no manager; everything else does.
    local needs_manager=0 s
    for s in "${scenarios[@]}"; do [[ "${s}" == validation ]] || needs_manager=1; done
    docker network create "${E2E_NET}" > /dev/null 2>&1 || true
    if [[ "${needs_manager}" -eq 1 ]]; then
        log "starting the Wazuh manager (this takes a minute)"
        manager_start
    fi

    for s in "${scenarios[@]}"; do
        "scenario_${s}"
    done
    summary
}

main "$@"
