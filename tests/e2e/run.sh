#!/usr/bin/env bash
# End-to-end tests: the app image against a real Wazuh manager.
#
#   IMAGE=ha-wazuh-agent:test tests/e2e/run.sh [scenario ...]
#
# Scenarios: validation enroll journal fim config supervisor ui capabilities upgrade crash duplicate reenroll
#            host host_cpu host_control host_unavailable host_incompatible host_packages host_apparmor password
#            (default: all, in this order. password is last: it makes the manager require a registration
#            password, which every enrollment after it would then fail without.)
#   host_apparmor loads the app's AppArmor profile and so only runs where AppArmor is enforced and
#   sudo is available (GitHub's runners); anywhere else it says so and is skipped.
#   The first group runs the agent in a plain container (monitor_host off). The host group runs it as
#   it runs in Home Assistant, against a stand-in for the Home Assistant OS device (see lib/host.sh).
# Environment: IMAGE (image under test), MANAGER_VERSION (default 4.14.9),
#              E2E_KEEP=1 to leave containers behind for debugging.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${HERE}/lib/common.sh"
# shellcheck source=lib/journal.sh
source "${HERE}/lib/journal.sh"
# shellcheck source=lib/host.sh
source "${HERE}/lib/host.sh"

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
    local id group_members
    id="$(manager_agent_id "${name}")"
    group_members="$(docker exec "${MANAGER}" /var/ossec/bin/agent_groups -l -g e2e-group 2> /dev/null)"
    grep -q "${id}" <<< "${group_members}" \
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
    return 0
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
scenario_supervisor() {
    log "supervisor: the agent name and Home Assistant labels come from the Supervisor API"
    # A stand-in Supervisor: static files at the two paths the app reads, reachable as
    # "supervisor" (the name Home Assistant gives the real one).
    local sup="e2e-supervisor-${E2E_ID}" web="e2e-sup-web-${E2E_ID}"
    local vol="e2e-sup-data-${E2E_ID}" logvol="e2e-sup-logs-${E2E_ID}" c="e2e-sup-agent-${E2E_ID}"
    track_container "${sup}"
    track_volume "${web}"
    track_volume "${logvol}"
    docker volume create "${web}" > /dev/null
    docker run --rm -v "${web}:/www" --entrypoint bash "${IMAGE}" -c '
        mkdir -p /www/addons/self
        cat > /www/info <<EOF
{"result": "ok", "data": {"hostname": "My HA Box", "operating_system": "Home Assistant OS 16.2", "hassos": "16.2",
 "homeassistant": "2026.10.1", "supervisor": "2026.10.0", "machine": "rpi4-64", "arch": "aarch64", "channel": "stable"}}
EOF
        cat > /www/addons/self/info <<EOF
{"result": "ok", "data": {"version": "9.9.9"}}
EOF'
    docker run -d --name "${sup}" --network "${E2E_NET}" --network-alias supervisor \
        -v "${web}:/www:ro" busybox:stable httpd -f -p 80 -h /www > /dev/null

    docker volume create "${logvol}" > /dev/null
    docker run --rm -v "${logvol}:/l" --entrypoint bash "${IMAGE}" -c 'touch /l/probe.log'
    # No agent_name: it must come from the Supervisor's hostname ("My HA Box" -> "My-HA-Box").
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", ${FAST},
        \"log_files\": [{\"path\": \"/logs/probe.log\", \"format\": \"syslog\"}]}"
    agent_start "${c}" "${vol}" -e SUPERVISOR_TOKEN=e2e-token -v "${logvol}:/logs"

    if wait_for 150 "agent active under the Supervisor's host name" manager_agent_active "My-HA-Box"; then
        pass "the agent name defaults to the Home Assistant host name (My-HA-Box)"
    else
        fail "the agent name defaults to the Home Assistant host name (My-HA-Box)"
        dump_agent "${c}"
        return
    fi
    agent_settle "${c}"
    wait_for 60 "log file picked up" container_log_has "${c}" "Analyzing file: '/logs/probe.log'"
    docker run --rm -v "${logvol}:/l" --entrypoint bash "${IMAGE}" -c \
        'echo "Oct 15 10:00:00 homeassistant e2eprobe: e2e-supervisor-probe" >> /l/probe.log'
    if wait_for 90 "event with labels" manager_has_archive "e2e-supervisor-probe"; then
        local event
        event="$(docker exec "${MANAGER}" bash -c "grep -F e2e-supervisor-probe /var/ossec/logs/archives/archives.json | head -1")"
        local label
        for label in '"ha_os_version":"16.2"' '"ha_core_version":"2026.10.1"' '"ha_supervisor_version":"2026.10.0"' \
            '"ha_machine":"rpi4-64"' '"ha_app_version":"9.9.9"'; do
            grep -qF -- "${label}" <<< "${event}" && pass "the event carries ${label}" || fail "the event carries ${label}"
        done
    else
        fail "an event reached the manager"
    fi
}

# ---------------------------------------------------------------------------
scenario_ui() {
    log "ui: the status page shows the agent's real state, read-only, unprivileged, ingress-only"
    local vol="e2e-ui-data-${E2E_ID}" c="e2e-ui-${E2E_ID}" name="e2e-ui"
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", \"ui_update_check\": false, ${FAST}}"
    # The default allow list is the Supervisor's ingress gateway; the test client is not that, so
    # open it for this container only. The closed one below keeps the default.
    agent_start "${c}" "${vol}" -e WAZUH_UI_ALLOW=0.0.0.0/0

    wait_for 150 "agent active" manager_agent_active "${name}" || { fail "agent active"; dump_agent "${c}"; return 0; }
    # The agent restarts once after its first connection (Wazuh asks); the test stops it later, and must not do
    # that while the app is restarting it for that.
    agent_settle "${c}"
    if wait_for 90 "the page reports running" ui_state_is "${c}" running; then
        pass "the page reports the agent as running"
    else
        fail "the page reports the agent as running (it says: $(ui_json "${c}" /api/status .state))"
        dump_agent "${c}"
        return 0
    fi

    local want_version status id
    want_version="$(docker image inspect "${IMAGE}" --format '{{ index .Config.Labels "com.wazuh.agent.version" }}')"
    status="$(ui_get "${c}" /api/status)"
    id="$(manager_agent_id "${name}")"
    [[ "$(jq -r .registration.id <<< "${status}")" == "${id}" ]] \
        && pass "the page shows the same agent ID as the manager (${id})" || fail "the page shows the same agent ID as the manager (${id})"
    [[ "$(jq -r .registration.name <<< "${status}")" == "${name}" ]] \
        && pass "the page shows the registered name" || fail "the page shows the registered name"
    [[ "$(jq -r .connection.status <<< "${status}")" == "connected" ]] \
        && pass "the page shows the connection as connected" || fail "the page shows the connection as connected"
    [[ "$(jq -r .summary.agent.version <<< "${status}")" == "${want_version}" ]] \
        && pass "the page shows the Wazuh version (${want_version})" || fail "the page shows the Wazuh version (${want_version})"
    [[ "$(jq -r '[.daemons[] | select(.name == "wazuh-agentd") | .running] | first' <<< "${status}")" == "true" ]] \
        && pass "the page lists the agent daemon as running" || fail "the page lists the agent daemon as running"
    [[ "$(jq -r .summary.modules.fim <<< "${status}")" == "true" ]] \
        && pass "the page shows file integrity monitoring as on" || fail "the page shows file integrity monitoring as on"

    # Nothing the page serves may carry the agent's key.
    local key everything
    key="$(docker exec "${c}" awk 'NR == 1 {print $4}' /var/ossec/etc/client.keys)"
    everything="${status}$(ui_get "${c}" /api/logs)$(ui_get "${c}" /api/connection-test)$(ui_get "${c}" /api/updates)"
    if [[ -n "${key}" ]] && ! grep -qF -- "${key}" <<< "${everything}"; then
        pass "the agent key appears in none of the page's responses"
    else
        fail "the agent key appears in none of the page's responses"
    fi

    [[ "$(ui_get "${c}" /api/logs | jq -r '.lines | map(select(contains("wazuh-agentd"))) | length')" -gt 0 ]] \
        && pass "the log tail carries the agent's lines" || fail "the log tail carries the agent's lines"
    [[ "$(ui_get "${c}" /api/connection-test | jq -r '[.results[] | select(.reachable)] | length')" -ge 2 ]] \
        && pass "the connection test reaches the manager's event and enrollment ports" || fail "the connection test reaches the manager's event and enrollment ports"
    [[ "$(ui_json "${c}" /api/updates .enabled)" == "false" ]] \
        && pass "ui_update_check=false turns the update lookup off" || fail "ui_update_check=false turns the update lookup off"

    # The page itself, and the files it loads.
    local html asset assets_ok=1
    html="$(ui_get "${c}" /)"
    grep -qF '<title>Wazuh Agent</title>' <<< "${html}" && pass "the page is served" || fail "the page is served"
    while IFS= read -r asset; do
        [[ "$(ui_code "${c}" "/${asset}")" == 200 ]] || assets_ok=0
    done < <(grep -oE 'assets/[^"]+' <<< "${html}")
    [[ "${assets_ok}" == 1 ]] && pass "every script and stylesheet the page loads is served" || fail "every script and stylesheet the page loads is served"
    [[ "$(ui_code "${c}" /assets/)" == 404 ]] && pass "directories are not listed" || fail "directories are not listed"
    [[ "$(ui_code "${c}" /api/status -X POST)" == 405 ]] && pass "the page is read-only (POST is refused)" || fail "the page is read-only (POST is refused)"
    # Capture the headers first: "curl | grep -q" fails when grep exits on the first match while curl
    # is still writing the other headers ("write /dev/stdout: broken pipe", and pipefail passes it on).
    local response_headers
    response_headers="$(ui_get "${c}" /api/status -D - -o /dev/null)"
    grep -qi '^content-security-policy:' <<< "${response_headers}" \
        && pass "responses carry a content security policy" || fail "responses carry a content security policy"

    # It runs without privileges.
    [[ "$(docker exec "${c}" ps -o user= -C wazuh-ha-ui | tr -d ' ')" == wazuhui ]] \
        && pass "the status page runs as the unprivileged wazuhui account" || fail "the status page runs as the unprivileged wazuhui account"

    # Stopped, and back.
    docker exec "${c}" /var/ossec/bin/wazuh-control stop > /dev/null 2>&1
    if wait_for 40 "the page shows the agent stopped" ui_state_is "${c}" stopped; then
        pass "the page shows the agent as stopped when it is"
    else
        fail "the page shows the agent as stopped when it is (it says: $(ui_json "${c}" /api/status .state))"
    fi
    if wait_for 200 "the page shows the agent running again" ui_state_is "${c}" running; then
        pass "the app brings the agent back and the page shows it running again"
    else
        fail "the app brings the agent back and the page shows it running again (it says: $(ui_json "${c}" /api/status .state))"
    fi

    # By default only the Supervisor's ingress gateway may connect.
    local closed="e2e-ui-closed-${E2E_ID}" cvol="e2e-ui-closed-data-${E2E_ID}"
    write_options "${cvol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"e2e-ui-closed\", ${FAST}}"
    agent_start "${closed}" "${cvol}"
    wait_for 60 "closed page up" container_log_has "${closed}" "Starting the status page"
    sleep 3
    [[ "$(ui_code "${closed}" /)" == 403 && "$(ui_code "${closed}" /api/status)" == 403 ]] \
        && pass "by default the page refuses everyone but the Supervisor's ingress gateway" \
        || fail "by default the page refuses everyone but the Supervisor's ingress gateway"
    return 0
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
    # Wazuh rewrites the file while enrolling, so the owner may be root or wazuh; what matters is
    # that it is group wazuh and not readable by everyone else.
    local keyperm
    keyperm="$(docker exec "${c}" stat -c '%U:%G %a' /data/ossec/etc/client.keys)"
    info "client.keys after re-enrollment: ${keyperm}"
    [[ "${keyperm}" =~ ^(root|wazuh):wazuh\ 6[04]0$ ]] \
        && pass "the new agent key is not world readable" || fail "the new agent key is not world readable (${keyperm})"
    container_log_has "${c}" 'force_reenroll is on' \
        && pass "the app warns that force_reenroll is on" || fail "the app warns that force_reenroll is on"
}

# ---------------------------------------------------------------------------
scenario_crash() {
    log "crash: a container killed mid-operation leaves state that must not block the next start"
    local vol="e2e-crash-data-${E2E_ID}" c="e2e-crash-${E2E_ID}" name="e2e-crash"
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c}" "${vol}"
    wait_for 150 "agent active" manager_agent_active "${name}" || { fail "agent active"; dump_agent "${c}"; return 0; }

    # No clean shutdown, like a power cut or a Supervisor timeout. Then plant what an interrupted
    # start leaves in the data: the lock wazuh-control takes, naming a process ID that is certainly
    # alive in the next container (1), and a daemon PID file of the dead run. Without the app
    # clearing them, wazuh-control honours the lock for every start, forever.
    docker kill "${c}" > /dev/null
    docker run --rm -v "${vol}:/data" --entrypoint bash "${IMAGE}" -c '
        mkdir -p /data/ossec/var/start-script-lock && echo 1 > /data/ossec/var/start-script-lock/pid
        echo 1 > /data/ossec/var/run/wazuh-agentd-1.pid'
    agent_start "${c}" "${vol}"

    if wait_for 150 "agent connected after the crash" docker exec "${c}" wazuh-ha-healthcheck; then
        pass "the agent starts and connects after an unclean stop that left a lock behind"
    else
        fail "the agent starts and connects after an unclean stop that left a lock behind"
        dump_agent "${c}"
    fi
    container_log_has "${c}" 'Another instance is locking' \
        && fail "no start lock error after a crash" || pass "no start lock error after a crash"
    assert "all agent daemons run after the crash" bash -c \
        "[[ \$(docker exec ${c} /var/ossec/bin/wazuh-control status | grep -c 'is running') -eq 5 ]]"
    return 0
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
# The app asks the Supervisor for no extra capabilities, so it gets Docker's default set (less
# what the Supervisor's "reduced" profile removes). Wazuh's documentation does not say which Linux
# capabilities the agent needs, so this measures it: the agent is run with the smallest set that
# works, with the set a current Supervisor leaves a container, and with none at all as a control.
CAPS_NEEDED=(CHOWN DAC_OVERRIDE FOWNER SETGID SETUID KILL)
CAPS_SUPERVISOR_DROPS=(NET_RAW AUDIT_WRITE MKNOD SETFCAP)

scenario_capabilities() {
    log "capabilities: the agent works with only ${CAPS_NEEDED[*]}, and not with none"
    local minimal="e2e-cap-min-${E2E_ID}" reduced="e2e-cap-red-${E2E_ID}" none="e2e-cap-none-${E2E_ID}"
    local args=() cap

    for cap in "${CAPS_NEEDED[@]}"; do args+=(--cap-add "${cap}"); done
    write_options "${minimal}-d" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"e2e-cap-min\", ${FAST}}"
    agent_start "${minimal}" "${minimal}-d" --cap-drop ALL "${args[@]}" -e WAZUH_UI_ALLOW=0.0.0.0/0

    args=()
    for cap in "${CAPS_SUPERVISOR_DROPS[@]}"; do args+=(--cap-drop "${cap}"); done
    write_options "${reduced}-d" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"e2e-cap-red\", ${FAST}}"
    agent_start "${reduced}" "${reduced}-d" "${args[@]}" -e WAZUH_UI_ALLOW=0.0.0.0/0

    write_options "${none}-d" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"e2e-cap-none\", ${FAST}}"
    agent_start "${none}" "${none}-d" --cap-drop ALL -e WAZUH_UI_ALLOW=0.0.0.0/0

    local c name
    for c in "${minimal}:e2e-cap-min:the minimal set" "${reduced}:e2e-cap-red:the Supervisor's reduced set"; do
        name="${c#*:}"
        name="${name%%:*}"
        local label="${c##*:}" container="${c%%:*}"
        if wait_for 150 "${name} active" manager_agent_active "${name}"; then
            pass "enrolls with ${label}"
        else
            fail "enrolls with ${label}"
            dump_agent "${container}"
            continue
        fi
        assert "is connected with ${label}" wait_for 150 "connected" docker exec "${container}" wazuh-ha-healthcheck
        assert "runs all five daemons with ${label}" bash -c \
            "[[ \$(docker exec ${container} /var/ossec/bin/wazuh-control status | grep -c 'is running') -eq 5 ]]"
        assert "the status page reports running with ${label}" wait_for 90 "running" ui_state_is "${container}" running
        container_log_has "${container}" 'Operation not permitted' \
            && fail "no permission errors in the log with ${label}" || pass "no permission errors in the log with ${label}"
    done

    # The control: with no capabilities at all the agent must not get as far as the manager, which is
    # what shows the two runs above passed because of the capabilities listed and not by accident.
    [[ -z "$(manager_agent_line e2e-cap-none)" ]] && ! docker exec "${none}" wazuh-ha-healthcheck > /dev/null 2>&1 \
        && pass "with no capabilities at all the agent cannot run (so the list above is needed)" \
        || fail "with no capabilities at all the agent cannot run (so the list above is needed)"
    return 0
}

# ---------------------------------------------------------------------------
# The app is the Wazuh agent of the Home Assistant OS device, not of its own container. The next
# scenarios run it against a stand-in for that device (lib/host.sh) and compare what the real Wazuh
# manager records with what the stand-in is, and with what the app's container is.

# The id of a Wazuh agent by name, once it has been enrolled for long enough to have an inventory.
HOST_HELPER_PATH="local_wazuh_agent/ossec/bin/"

scenario_host() {
    log "host: what the manager records about the agent is the host's, not the container's"
    local vol="e2e-host-data-${E2E_ID}" cfg="e2e-host-cfg-${E2E_ID}" ssl="e2e-host-ssl-${E2E_ID}"
    local jvol="e2e-host-jvol-${E2E_ID}" jw="e2e-host-jw-${E2E_ID}"
    local h="e2e-host-${E2E_ID}" c="e2e-host-agent-${E2E_ID}" name="e2e-host-agent"
    track_volume "${cfg}"
    track_volume "${ssl}"
    track_volume "${jvol}"
    track_container "${jw}"
    docker volume create "${cfg}" > /dev/null
    docker volume create "${ssl}" > /dev/null
    journal_writer_start "${jw}" "${jvol}" "${JOURNAL_MID}" || { fail "the journal writer started"; return 0; }
    write_options "${vol}" "{\"monitor_host\": true, \"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    host_start "${h}" "${vol}" -e "HOST_MACHINE_ID=${JOURNAL_MID}" \
        -v "${cfg}:/mnt/data/supervisor/homeassistant" -v "${ssl}:/mnt/data/supervisor/ssl" -v "${jvol}:/var/log/journal:ro" \
        || { fail "the stand-in host started"; return 0; }
    # The folders Home Assistant maps into the app are the same folders as the host's.
    host_agent_start "${c}" "${vol}" "${h}" -v "${cfg}:/homeassistant:ro" -v "${ssl}:/ssl:ro" -v "${jvol}:/var/log/journal:ro"

    if wait_for 180 "agent active" manager_agent_active "${name}"; then
        pass "the agent enrolled and is Active at the manager"
    else
        fail "the agent enrolled and is Active at the manager"
        dump_agent "${c}"
        return 0
    fi
    host_settle "${c}"
    local id host_ip image_os
    id="$(manager_agent_id "${name}")"
    host_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${h}")"
    image_os="$(docker run --rm --entrypoint sed "${IMAGE}" -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release)"

    # --- where the agent runs
    container_log_has "${c}" "The agent will run in the host's file system" \
        && pass "the app says the agent runs in the host's file system" || fail "the app says the agent runs in the host's file system"
    check_equal "the agent daemon runs from the host's own path of the app's data" \
        "$(docker exec "${c}" bash -c 'readlink /proc/$(cat /var/ossec/var/run/wazuh-agentd-*.pid)/exe')" \
        "${HOST_DATA_PATH}/ossec/bin/wazuh-agentd"
    check_different "the daemons are not in the app container's mount namespace" \
        "$(docker exec "${c}" bash -c 'readlink /proc/$(cat /var/ossec/var/run/wazuh-agentd-*.pid)/ns/mnt')" \
        "$(docker exec "${c}" readlink /proc/self/ns/mnt)"
    check_equal "the app translates its own folders to the host's" \
        "$(docker exec "${c}" wazuh-ha-host path /homeassistant)" "/mnt/data/supervisor/homeassistant"

    # --- what the manager records about this agent
    check_equal "the agent's address is the host's (${host_ip})" \
        "$(manager_item "/agents?q=name=${name}&select=ip" '.ip')" "${host_ip}"
    check_equal "the agent's operating system is the host's (${HOST_OS_NAME})" \
        "$(manager_item "/agents?q=name=${name}&select=os.name" '.os.name')" "${HOST_OS_NAME}"
    check_different "... and not the container image's (${image_os})" \
        "$(manager_item "/agents?q=name=${name}&select=os.name" '.os.name')" "${image_os}"
    check_equal "the inventory's operating system is the host's" \
        "$(manager_item "/syscollector/${id}/os" '.os.name + " " + .os.version + " (" + .os.platform + ")"')" \
        "${HOST_OS_NAME} ${HOST_OS_VERSION} (haos)"
    check_equal "the inventory's host name is the host's" \
        "$(manager_item "/syscollector/${id}/os" '.hostname')" "${HOST_HOSTNAME}"
    check_different "the inventory names the CPU (a real name on x86, a worked-out one on ARM)" \
        "$(manager_item "/syscollector/${id}/hardware" '.cpu.name')" "-"

    # --- the processes and ports of the whole device, not of the app's container
    [[ "$(manager_api "/syscollector/${id}/processes?search=perl&limit=1" | jq -r '.data.total_affected_items')" -ge 1 ]] \
        && pass "the host's own processes are in the inventory" || fail "the host's own processes are in the inventory"
    [[ "$(manager_api "/syscollector/${id}/processes?search=wazuh-analysisd&limit=1" | jq -r '.data.total_affected_items')" -ge 1 ]] \
        && pass "so are the processes of other containers on the device (the manager's)" \
        || fail "so are the processes of other containers on the device (the manager's)"
    check_equal "the host's listening port 4242 is in the inventory, with the process that opened it" \
        "$(manager_api "/syscollector/${id}/ports?search=perl" | jq -r '[.data.affected_items[] | select(.local.port == 4242) | .process] | first')" "perl"
    local accounts
    accounts="$(manager_api "/syscollector/${id}/users?limit=500" | jq -r '[.data.affected_items[].user.name] | join(" ")')"
    [[ " ${accounts} " == *" root "* && " ${accounts} " == *" wazuh "* ]] \
        && pass "the host's accounts are in the inventory, with the wazuh account the agent runs as" \
        || fail "the host's accounts are in the inventory, with the wazuh account the agent runs as (got: ${accounts})"
    [[ " ${accounts} " != *" wazuhui "* ]] \
        && pass "the app container's own accounts are not" || fail "the app container's own accounts are not"

    # --- file integrity of the host's own files, under the host's own paths
    docker exec "${h}" bash -c '
        echo "X11Forwarding yes" >> /etc/ssh/sshd_config
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIe2eFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF intruder" >> /root/.ssh/authorized_keys
        echo "homeassistant:" > /mnt/data/supervisor/homeassistant/configuration.yaml'
    local path
    for path in /etc/ssh/sshd_config /root/.ssh/authorized_keys /mnt/data/supervisor/homeassistant/configuration.yaml; do
        if wait_for 90 "FIM alert ${path}" manager_has_alert_path "${path}"; then
            pass "file integrity alert for the host's ${path}"
        else
            fail "file integrity alert for the host's ${path}"
        fi
    done
    [[ "$(manager_alert_count_for "${name}" '"path":"/homeassistant/')" == 0 ]] \
        && pass "no alert of this agent carries the app's own path of the Home Assistant folder" \
        || fail "no alert of this agent carries the app's own path of the Home Assistant folder"

    # --- the host's journal
    journal_emit "${jw}" sshd 5 "Failed password for invalid user e2ehost from 192.0.2.31 port 4001 ssh2"
    wait_for 90 "journal event" manager_has_archive 192.0.2.31 \
        && pass "an event of the host's journal reached the manager" || fail "an event of the host's journal reached the manager"

    # --- the restart Wazuh asked for was done by the app, not through systemd
    docker exec "${c}" grep -q 'ask the app' /var/ossec/active-response/bin/restart.sh \
        && pass "Wazuh's restart.sh is the app's, which asks the app to restart the agent" \
        || fail "Wazuh's restart.sh is the app's, which asks the app to restart the agent"
    docker exec "${h}" test ! -s /tmp/systemctl.log \
        && pass "the host's systemctl was never asked to restart anything" || fail "the host's systemctl was never asked to restart anything"

    # --- the status page
    local status
    status="$(ui_get "${h}" /api/status)"
    check_equal "the page reports the agent as running" "$(jq -r .state <<< "${status}")" running
    check_equal "the page says the agent monitors the host" "$(jq -r .access.scope <<< "${status}")" host
    check_equal "and shows the host's name" "$(jq -r .summary.host.scope <<< "${status}")" host

    # --- the host itself was left alone
    check_equal "no wazuh account was added to the host's /etc/passwd" \
        "$(docker exec "${h}" bash -c 'grep -c "^wazuh:" /etc/passwd || true')" 0
    check_equal "no wazuh group was added to the host's /etc/group" \
        "$(docker exec "${h}" bash -c 'grep -c "^wazuh:" /etc/group || true')" 0
    check_equal "nothing the app mounted shows in the host's mounts" \
        "$(docker exec "${h}" bash -c 'grep -c "hostview\|hostbin" /proc/self/mountinfo || true')" 0
    check_equal "the agent's private /home is not mounted on the host" \
        "$(docker exec "${h}" bash -c 'grep -c " /home " /proc/self/mountinfo || true')" 0

    # --- the app restarts, the agent keeps its identity; and stops, leaving nothing behind
    docker restart "${c}" > /dev/null
    assert "the agent reconnects after the app restarts" wait_for 180 "reconnected" docker exec "${c}" wazuh-ha-healthcheck
    check_equal "the agent kept its manager-side identity" "$(manager_agent_id "${name}")" "${id}"
    docker stop "${c}" > /dev/null
    check_equal "stopping the app stops every daemon it started on the host" \
        "$(docker run --rm --pid=host --cap-add SYS_PTRACE --entrypoint bash "${IMAGE}" -c \
            "for p in /proc/[0-9]*; do readlink \$p/exe 2> /dev/null; done | grep -c '${HOST_HELPER_PATH}' || true")" 0
    return 0
}

# ---------------------------------------------------------------------------
scenario_host_cpu() {
    log "host_cpu: an ARM CPU, which Wazuh cannot name by itself, is named in the inventory"
    local vol="e2e-hcpu-data-${E2E_ID}" h="e2e-hcpu-${E2E_ID}" c="e2e-hcpu-agent-${E2E_ID}" name="e2e-hcpu-agent"
    local sample="${HERE}/../fixtures/host/cpuname/rpi5.cpuinfo"
    write_options "${vol}" "{\"monitor_host\": true, \"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    host_start "${h}" "${vol}" || { fail "the stand-in host started"; return 0; }
    # A Raspberry Pi 5's /proc/cpuinfo, which has no "model name", whatever machine the test runs on.
    host_agent_start "${c}" "${vol}" "${h}" -v "${sample}:/cpuinfo-sample:ro" \
        -e WAZUH_HA_CPUINFO=/cpuinfo-sample -e WAZUH_HA_BOARD_FILE=/nonexistent
    if ! wait_for 180 "agent active" manager_agent_active "${name}"; then
        fail "the agent enrolled and is Active at the manager"
        dump_agent "${c}"
        return 0
    fi
    local id
    id="$(manager_agent_id "${name}")"
    check_equal "the inventory names the Raspberry Pi 5's CPU, which its kernel does not" \
        "$(manager_item "/syscollector/${id}/hardware" '.cpu.name')" "Cortex-A76 (Raspberry Pi 5 Model B Rev 1.0)"
    check_equal "and counts its four cores" "$(manager_item "/syscollector/${id}/hardware" '.cpu.cores')" 4
    check_equal "the host's own /proc/cpuinfo was not changed" \
        "$(docker exec "${h}" bash -c 'grep -c "Cortex" /proc/cpuinfo || true')" 0
    return 0
}

# ---------------------------------------------------------------------------
scenario_host_control() {
    log "host_control: without host monitoring the manager records the container, so the host checks above mean something"
    local vol="e2e-hctl-data-${E2E_ID}" c="e2e-hctl-${E2E_ID}" name="e2e-hctl"
    write_options "${vol}" "{\"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    agent_start "${c}" "${vol}"
    if ! wait_for 150 "agent active" manager_agent_active "${name}"; then
        fail "the agent enrolled and is Active at the manager"
        dump_agent "${c}"
        return 0
    fi
    local id container_ip os_name
    id="$(manager_agent_id "${name}")"
    container_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${c}")"
    os_name="$(manager_item "/syscollector/${id}/os" '.os.name')"
    check_equal "the agent's address is the container's" "$(manager_item "/agents?q=name=${name}&select=ip" '.ip')" "${container_ip}"
    [[ "${os_name}" == *Debian* ]] && pass "the operating system is the container image's (${os_name})" \
        || fail "the operating system is the container image's (${os_name})"
    check_different "... and not the host's" "${os_name}" "${HOST_OS_NAME}"
    return 0
}

# ---------------------------------------------------------------------------
scenario_host_unavailable() {
    log "host_unavailable: when the host cannot be reached nothing runs, and the status page and the log say why"
    # A stand-in Supervisor that answers for this app: its protection mode is whatever the file says.
    local sup="e2e-hu-sup-${E2E_ID}" web="e2e-hu-web-${E2E_ID}"
    track_container "${sup}"
    track_volume "${web}"
    docker volume create "${web}" > /dev/null
    set_protection() {
        local protected="$1"
        docker run --rm -v "${web}:/www" --entrypoint bash "${IMAGE}" -c "
            mkdir -p /www/addons/self
            echo '{\"result\": \"ok\", \"data\": {\"hostname\": \"homeassistant\", \"operating_system\": \"Home Assistant OS 17.0\"}}' > /www/info
            echo '{\"result\": \"ok\", \"data\": {\"version\": \"9.9.9\", \"protected\": ${protected}}}' > /www/addons/self/info"
        return 0
    }
    set_protection true
    docker run -d --name "${sup}" --network "${E2E_NET}" --network-alias supervisor \
        -v "${web}:/www:ro" busybox:stable httpd -f -p 80 -h /www > /dev/null

    local case_name vol c extra reason expect health
    # NAME|extra docker options|reason the page must give|text the message must contain
    while IFS='|' read -r case_name extra reason expect; do
        vol="e2e-hu-${case_name}-${E2E_ID}"
        c="e2e-hu-${case_name}-c-${E2E_ID}"
        [[ "${case_name}" == restart ]] && set_protection false
        write_options "${vol}" "{\"monitor_host\": true, \"manager_address\": \"${MANAGER}\", \"agent_name\": \"e2e-hu-${case_name}\", ${FAST}}"
        # shellcheck disable=SC2086
        agent_start "${c}" "${vol}" -e SUPERVISOR_TOKEN=e2e-token -e WAZUH_UI_ALLOW=0.0.0.0/0 ${extra}
        if wait_for 90 "${case_name}: the page asks for host access" ui_state_is "${c}" needs_host_access; then
            pass "${case_name}: the status page says host access is needed"
        else
            fail "${case_name}: the status page says host access is needed (it says: $(ui_json "${c}" /api/status .state))"
            dump_agent "${c}"
            continue
        fi
        check_equal "${case_name}: the reason is ${reason}" "$(ui_json "${c}" /api/status .access.reason)" "${reason}"
        [[ "$(ui_json "${c}" /api/status .detail)" == *"${expect}"* ]] \
            && pass "${case_name}: the page tells the user what to do (${expect})" \
            || fail "${case_name}: the page tells the user what to do (${expect})"
        container_log_has "${c}" "The Wazuh agent was not started (${reason})" \
            && pass "${case_name}: the app log says why nothing was started" || fail "${case_name}: the app log says why nothing was started"
        [[ -z "$(manager_agent_line "e2e-hu-${case_name}")" ]] \
            && pass "${case_name}: no agent was registered with the manager" || fail "${case_name}: no agent was registered with the manager"
        # The output is captured first: "docker exec | grep -q" fails under pipefail when grep exits early.
        health="$(docker exec "${c}" wazuh-ha-healthcheck 2>&1)"
        grep -q 'host access' <<< "${health}" \
            && pass "${case_name}: the container reports itself unhealthy, for that reason" \
            || fail "${case_name}: the container reports itself unhealthy, for that reason (${health})"
        check_equal "${case_name}: no daemon of the agent runs" \
            "$(docker exec "${c}" bash -c 'pgrep -fc "[o]ssec/bin/wazuh-" || true')" 0
    done << 'CASES'
default||missing_capabilities|SYS_ADMIN
protected|--cap-add SYS_ADMIN --cap-add SYS_PTRACE|protection_mode|Protection mode off
restart|--cap-add SYS_ADMIN --cap-add SYS_PTRACE|restart_needed|Restart the app
CASES
    return 0
}

# ---------------------------------------------------------------------------
scenario_host_packages() {
    log "host_packages: Home Assistant Core's Python packages are in the inventory, and follow Core when it restarts"
    local vol="e2e-hpkg-data-${E2E_ID}" h="e2e-hpkg-${E2E_ID}" core="e2e-hpkg-core-${E2E_ID}" c="e2e-hpkg-agent-${E2E_ID}"
    local name="e2e-hpkg-agent"
    # A short inventory interval, so a change in Core's packages shows within the test.
    write_options "${vol}" "{\"monitor_host\": true, \"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", \"inventory_interval\": \"20s\", ${FAST}}"
    host_start "${h}" "${vol}" || { fail "the stand-in host started"; return 0; }
    # A stand-in for Home Assistant Core: a process called as Core's is (python3 -m homeassistant), in a
    # container of its own with the Python packages where the official image keeps them. It holds a
    # package with a known advisory, so that it is one worth finding.
    docker run -d --name "${core}" --network "${E2E_NET}" --pid=host debian:bookworm-slim bash -c '
        site=/usr/local/lib/python3.13/site-packages
        mkdir -p "${site}/aiohttp-3.9.0.dist-info" "${site}/requests-2.19.0.dist-info"
        printf "Name: aiohttp\nVersion: 3.9.0\n" > "${site}/aiohttp-3.9.0.dist-info/METADATA"
        printf "Name: requests\nVersion: 2.19.0\n" > "${site}/requests-2.19.0.dist-info/METADATA"
        exec -a "python3 -m homeassistant --config /config" sleep infinity' > /dev/null
    track_container "${core}"
    host_agent_start "${c}" "${vol}" "${h}"
    if ! wait_for 180 "agent active" manager_agent_active "${name}"; then
        fail "the agent enrolled and is Active at the manager"
        dump_agent "${c}"
        return 0
    fi
    local id
    id="$(manager_agent_id "${name}")"

    package_in_inventory() { # NAME VERSION -> succeeds when the manager lists that Python package at that version
        local package="$1" version="$2"
        manager_api "/syscollector/${id}/packages?search=${package}&limit=5" \
            | jq -e --arg version "${version}" '.data.affected_items | map(select(.version == $version and .format == "pypi")) | length > 0'
        return
    }
    if wait_for 150 "Core's packages" package_in_inventory aiohttp 3.9.0; then
        pass "a Python package of Home Assistant Core is in the inventory (aiohttp 3.9.0)"
    else
        fail "a Python package of Home Assistant Core is in the inventory (aiohttp 3.9.0)"
        dump_agent "${c}"
        return 0
    fi
    package_in_inventory requests 2.19.0 > /dev/null \
        && pass "so are the others" || fail "so are the others"
    container_log_has "${c}" "Could not mount a /home" \
        && fail "the agent got a /home for the packages" || pass "the agent got a /home for the packages"
    check_equal "the host's own /home is untouched (the agent's /home is private)" \
        "$(docker exec "${h}" bash -c 'ls -A /home | wc -l')" "$(docker run --rm --entrypoint bash debian:bookworm-slim -c 'ls -A /home | wc -l')"

    # Core restarts: it gets a new process, and the packages it has now are the ones to find.
    local before after
    before="$(docker exec "${c}" readlink /data/hostview/corepython)"
    docker restart "${core}" > /dev/null
    docker exec "${core}" bash -c '
        site=/usr/local/lib/python3.13/site-packages
        mkdir -p "${site}/flask-3.0.0.dist-info"
        printf "Name: flask\nVersion: 3.0.0\n" > "${site}/flask-3.0.0.dist-info/METADATA"'
    if wait_for 120 "the link follows Core" bash -c "[[ \"\$(docker exec ${c} readlink /data/hostview/corepython)\" != \"${before}\" ]]"; then
        after="$(docker exec "${c}" readlink /data/hostview/corepython)"
        pass "after Core restarts the agent's link points at its new process"
        info "was ${before}, is ${after}"
    else
        fail "after Core restarts the agent's link points at its new process"
    fi
    wait_for 120 "a package that is new since" package_in_inventory flask 3.0.0 \
        && pass "the agent sees Core's packages as they are after the restart (flask 3.0.0, installed meanwhile)" \
        || fail "the agent sees Core's packages as they are after the restart (flask 3.0.0, installed meanwhile)"
    return 0
}

# ---------------------------------------------------------------------------
scenario_host_incompatible() {
    log "host_incompatible: a device whose system cannot run the agent is reported on the status page, not retried silently"
    local vol="e2e-hinc-data-${E2E_ID}" h="e2e-hinc-${E2E_ID}" c="e2e-hinc-agent-${E2E_ID}" name="e2e-hinc-agent"
    write_options "${vol}" "{\"monitor_host\": true, \"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    # A device without glibc (Alpine uses musl): the loader the Wazuh agent was built for is not there.
    docker run -d --name "${h}" --hostname haos-musl --network "${E2E_NET}" --pid=host --cap-add SYS_ADMIN \
        --security-opt apparmor=unconfined -v "${vol}:${HOST_DATA_PATH}" alpine:3 sh -c 'mount --make-rshared /; touch /tmp/host-ready; exec sleep 100000' > /dev/null
    track_container "${h}"
    wait_for 60 "the stand-in host is ready" docker exec "${h}" test -f /tmp/host-ready || { fail "the stand-in host started"; return 0; }
    host_agent_start "${c}" "${vol}" "${h}"

    if wait_for 120 "the page reports that the agent cannot start" ui_state_is "${h}" needs_host_access; then
        pass "the status page says host access is needed"
    else
        fail "the status page says host access is needed (it says: $(ui_json "${h}" /api/status .state))"
        dump_agent "${c}"
        return 0
    fi
    check_equal "the reason is that the agent cannot run in the host's system" "$(ui_json "${h}" /api/status .access.reason)" probe_failed
    [[ "$(ui_json "${h}" /api/status .detail)" == *"could not start in the host's file system"* ]] \
        && pass "the page says what failed" || fail "the page says what failed"
    container_log_has "${c}" "No such file or directory" \
        && pass "the app log shows what the host answered" || fail "the app log shows what the host answered"
    [[ -z "$(manager_agent_line "${name}")" ]] \
        && pass "no agent was registered with the manager" || fail "no agent was registered with the manager"
    local health
    health="$(docker exec "${c}" wazuh-ha-healthcheck 2>&1)"
    grep -q 'probe_failed' <<< "${health}" \
        && pass "the container reports itself unhealthy, for that reason" || fail "the container reports itself unhealthy (${health})"
    # It keeps trying (a device is fixed by a person, but the app must not give up), and keeps the page up.
    wait_for 90 "a second attempt" container_log_has_at_least "${c}" "Starting the Wazuh agent daemons." 2 \
        && pass "the app tries again after a pause" || fail "the app tries again after a pause"
    check_equal "the status page is still served" "$(ui_code "${h}" /api/status)" 200
    return 0
}

# ---------------------------------------------------------------------------
# The app's AppArmor profile is enforced on Home Assistant OS, and cannot be on a development machine
# whose kernel has AppArmor off, so this runs where it can be (GitHub's runners): the profile is loaded
# and the agent runs against the stand-in device under it, as the Supervisor would run it.
scenario_host_apparmor() {
    log "host_apparmor: with the app's AppArmor profile enforced, the agent works and nothing it needs is denied"
    if ! apparmor_available; then
        info "AppArmor is not enforced here (or sudo is missing): skipped"
        return 0
    fi
    local profile_file="${HERE}/../../wazuh_agent/apparmor.txt" profile=wazuh_agent
    local vol="e2e-haa-data-${E2E_ID}" cfg="e2e-haa-cfg-${E2E_ID}" ssl="e2e-haa-ssl-${E2E_ID}"
    local h="e2e-haa-${E2E_ID}" c="e2e-haa-agent-${E2E_ID}" name="e2e-haa-agent"
    track_volume "${cfg}"
    track_volume "${ssl}"
    docker volume create "${cfg}" > /dev/null
    docker volume create "${ssl}" > /dev/null
    if sudo -n apparmor_parser -r "${profile_file}"; then
        pass "the profile loads into the kernel"
    else
        fail "the profile loads into the kernel"
        return 0
    fi
    write_options "${vol}" "{\"monitor_host\": true, \"manager_address\": \"${MANAGER}\", \"agent_name\": \"${name}\", ${FAST}}"
    host_start "${h}" "${vol}" -v "${cfg}:/mnt/data/supervisor/homeassistant" -v "${ssl}:/mnt/data/supervisor/ssl" \
        || { fail "the stand-in host started"; return 0; }
    local before after control
    before="$(apparmor_denials "${profile}")"
    host_agent_start "${c}" "${vol}" "${h}" --security-opt "apparmor=${profile}" -v "${cfg}:/homeassistant:ro" -v "${ssl}:/ssl:ro"

    if wait_for 180 "agent active" manager_agent_active "${name}"; then
        pass "the agent enrolls and is Active with the profile enforced"
    else
        fail "the agent enrolls and is Active with the profile enforced"
        dump_agent "${c}"
        sudo -n dmesg 2> /dev/null | grep "apparmor=\"DENIED\".*profile=\"${profile}\"" | tail -8 | sed 's/^/    | /'
        sudo -n apparmor_parser -R "${profile_file}" || true
        return 0
    fi
    host_settle "${c}"
    local id
    id="$(manager_agent_id "${name}")"
    check_equal "the inventory is the host's under the profile" \
        "$(manager_item "/syscollector/${id}/os" '.os.name')" "${HOST_OS_NAME}"
    docker exec "${h}" bash -c 'echo "X11Forwarding yes" >> /etc/ssh/sshd_config'
    wait_for 90 "FIM alert" manager_has_alert_path /etc/ssh/sshd_config \
        && pass "file integrity of the host's files works under the profile" \
        || fail "file integrity of the host's files works under the profile"
    assert "the agent is connected after Wazuh's restart, which the app did under the profile" \
        docker exec "${c}" wazuh-ha-healthcheck

    # The kernel log, before and after: every denial of this profile is a line in it.
    after="$(apparmor_denials "${profile}")"
    check_equal "the profile denied nothing the agent needed" "$((after - before))" 0
    if [[ "$((after - before))" -ne 0 ]]; then
        apparmor_log "${profile}" | tail -n 8 | sed 's/^/    | /'
    fi
    # The control: a signal to a process that is not the app's own is what the profile refuses, and the
    # kernel log must show it, or the zero above would mean nothing.
    docker exec "${c}" bash -c 'kill -0 1' > /dev/null 2>&1 || true
    sleep 2
    control="$(apparmor_denials "${profile}")"
    if [[ "${control}" -gt "${after}" ]]; then
        pass "(control) a signal the profile forbids is denied and logged"
    else
        fail "(control) a signal the profile forbids is denied and logged"
        info "what the logs say about AppArmor:"
        apparmor_sample
    fi
    sudo -n apparmor_parser -R "${profile_file}" > /dev/null 2>&1 || true
    return 0
}

# ---------------------------------------------------------------------------
main() {
    local scenarios=("$@")
    [[ ${#scenarios[@]} -gt 0 ]] || scenarios=(validation enroll journal fim config supervisor ui capabilities upgrade crash duplicate reenroll host host_cpu host_control host_unavailable host_incompatible host_packages host_apparmor password)

    log "image under test: ${IMAGE}   manager: wazuh-manager ${MANAGER_VERSION}"
    # Validation needs no manager; everything else does.
    local needs_manager=0 s
    for s in "${scenarios[@]}"; do [[ "${s}" == validation ]] || needs_manager=1; done
    docker network create "${E2E_NET}" > /dev/null 2>&1 || true
    if [[ "${needs_manager}" -eq 1 ]]; then
        log "starting the Wazuh manager (this takes a minute)"
        manager_start
    fi

    local first_c first_v
    for s in "${scenarios[@]}"; do
        first_c=${#E2E_CONTAINERS[@]}
        first_v=${#E2E_VOLUMES[@]}
        "scenario_${s}"
        # E2E_KEEP leaves everything for debugging, as it does at the end.
        [[ -n "${E2E_KEEP:-}" ]] || release_since "${first_c}" "${first_v}"
    done
    summary
    return
}

main "$@"
