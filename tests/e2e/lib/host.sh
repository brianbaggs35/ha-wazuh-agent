#!/usr/bin/env bash
# Helpers for the host-mode end-to-end tests. Source this file; do not run it.
#
# The app is the Wazuh agent of the Home Assistant OS device itself. To test that against a real
# Wazuh manager without a Home Assistant OS machine, a container stands in for the device ("the
# host"). It shares the host's process namespace, which is where Home Assistant puts an app that
# asks for host_pid, and has a file system, host name, network address, files and processes of its
# own, made to look like a Home Assistant OS device's and made different from the app's on purpose.
# The app container joins its network (what host_network does) and is pointed at its init
# (WAZUH_HA_HOST_PID, which in Home Assistant is always PID 1), so what the manager records about
# the agent can be compared with what the stand-in is and with what the app's own container is.
#
#   host_start NAME DATA-VOLUME [docker run options...]             start the stand-in device
#   python_program_start NAME COMMAND-LINE PACKAGE:VERSION...       start a stand-in for Core or the Supervisor
#   host_agent_start NAME DATA-VOLUME HOST [docker run options...]  start the app, in host mode
#   host_settle CONTAINER                                           wait out the agent's first restart
#   manager_api PATH                                                the manager API's answer (JSON)
#   manager_agent_ip / manager_knows_agent_ip                       the address the manager has for an agent
#   sca_checks / sca_result / sca_has_all_results ...               what the manager has of the app's SCA policy
#   check_equal / check_different DESCRIPTION ACTUAL EXPECTED       one assertion

HOST_IMAGE="${HOST_IMAGE:-debian:bookworm-slim}"
# What the stand-ins for Home Assistant Core and the Supervisor are made of: the official Python image, which keeps
# Python where Home Assistant's own containers (built on the same layout) do, in /usr/local.
PY_IMAGE="${PY_IMAGE:-python:3.14-slim}"
HOST_HOSTNAME="haos-e2e"
# Where a Home Assistant OS device keeps this app's /data.
HOST_DATA_PATH="/mnt/data/supervisor/addons/data/local_wazuh_agent"
# What a Home Assistant OS device calls itself (os-release), as the manager must see it. Used by the
# scenarios that source this file.
# shellcheck disable=SC2034
HOST_OS_NAME="Home Assistant OS"
# shellcheck disable=SC2034
HOST_OS_VERSION="17.0"

# host_start NAME DATA-VOLUME [docker run options...]
# The stand-in device. It has the app's data volume where the host keeps it, and:
#   * /etc/os-release of Home Assistant OS, an sshd_config, root's SSH keys and a boot partition
#   * mount propagation "shared", as systemd leaves a real host's, which the app has to cope with
#   * a systemctl that records every call and fails, like a host with no wazuh-agent service
#   * the Docker socket's place (/run/docker.sock, mode 0660 as Home Assistant OS creates it), as a plain file
#   * a process listening on port 4242, for the inventory to find
host_start() {
    local name="$1" volume="$2"
    shift 2
    docker rm -f "${name}" > /dev/null 2>&1 || true
    docker run -d --name "${name}" --hostname "${HOST_HOSTNAME}" --network "${E2E_NET}" --pid=host \
        --cap-add SYS_ADMIN --security-opt apparmor=unconfined -v "${volume}:${HOST_DATA_PATH}" "$@" "${HOST_IMAGE}" bash -c '
        mount --make-rshared /
        mkdir -p /etc/ssh /root/.ssh /mnt/boot /mnt/data/supervisor/addons/local /run/systemd/system
        printf "%s\n" "NAME=\"Home Assistant OS\"" "VERSION=\"17.0\"" "ID=haos" "VERSION_ID=\"17.0\"" \
            "PRETTY_NAME=\"Home Assistant OS 17.0\"" > /etc/os-release
        echo "PermitRootLogin no" > /etc/ssh/sshd_config
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIe2e000000000000000000000000000000000000 e2e" > /root/.ssh/authorized_keys
        [ -z "${HOST_MACHINE_ID:-}" ] || echo "${HOST_MACHINE_ID}" > /etc/machine-id
        printf "#!/bin/sh\necho \"\$*\" >> /tmp/systemctl.log\nexit 5\n" > /usr/bin/systemctl
        chmod +x /usr/bin/systemctl
        touch /run/docker.sock
        chmod 660 /run/docker.sock
        perl -MIO::Socket::INET -e "my \$socket = IO::Socket::INET->new(Listen => 5, LocalPort => 4242, ReuseAddr => 1) or die; sleep" &
        touch /tmp/host-ready
        exec sleep infinity' > /dev/null
    track_container "${name}"
    wait_for 60 "the stand-in host is ready" docker exec "${name}" test -f /tmp/host-ready
    return
}

# python_program_start NAME COMMAND-LINE PACKAGE:VERSION...
# A stand-in for one of Home Assistant's Python programs, with the command line it really has (the arguments to
# python3, which docker run does not mangle: "-P -m homeassistant --config /config" is Core's since 2026.9, and
# "-m supervisor" the Supervisor's) and the Python packages it holds, where the Python image keeps them. The
# module it runs is a stub that sleeps. It shares the host's process namespace, as every container's processes
# are visible there on a real device.
python_program_start() {
    local name="$1" command="$2"
    shift 2
    docker rm -f "${name}" > /dev/null 2>&1 || true
    docker run -d --name "${name}" --network "${E2E_NET}" --pid=host "${PY_IMAGE}" bash -c '
        command="$1"
        shift
        module="${command#*-m }"
        module="${module%% *}"
        site="$(python3 -c "import sysconfig; print(sysconfig.get_paths()[\"purelib\"])")"
        mkdir -p "${site}/${module}"
        : > "${site}/${module}/__init__.py"
        printf "import time\ntime.sleep(10**9)\n" > "${site}/${module}/__main__.py"
        for package in "$@"; do
            dist="${site}/${package%%:*}-${package##*:}.dist-info"
            mkdir -p "${dist}"
            printf "Name: %s\nVersion: %s\n" "${package%%:*}" "${package##*:}" > "${dist}/METADATA"
        done
        # shellcheck disable=SC2086  # the command line is meant to be split into its arguments
        exec python3 ${command}' _ "${command}" "$@" > /dev/null
    track_container "${name}"
    return 0
}

# host_agent_start NAME DATA-VOLUME HOST [docker run options...]
# The app, started the way Home Assistant starts it with host_network, host_pid, host_uts and the
# SYS_ADMIN and SYS_PTRACE capabilities, and Protection mode off: in the stand-in's network, in the
# host's process namespace, under Docker's init, with seccomp off (the Supervisor turns it off for
# every app) and AppArmor off unless a profile is named in the options.
host_agent_start() {
    local name="$1" volume="$2" host="$3" pid arg apparmor=(--security-opt apparmor=unconfined)
    shift 3
    # Docker's own AppArmor profile (docker-default, which Ubuntu applies to every container) denies mount
    # even to a container with SYS_ADMIN. Home Assistant never runs an app under it: it uses the app's
    # profile, or none. So the app runs unconfined here unless the caller names the profile to run under.
    for arg in "$@"; do
        [[ "${arg}" == apparmor=* ]] && apparmor=()
    done
    pid="$(docker inspect -f '{{.State.Pid}}' "${host}")"
    docker rm -f "${name}" > /dev/null 2>&1 || true
    docker run -d --init --name "${name}" --network "container:${host}" --pid=host \
        --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt seccomp=unconfined "${apparmor[@]}" \
        -e "WAZUH_HA_HOST_PID=${pid}" -e WAZUH_UI_ALLOW=0.0.0.0/0 \
        -v "${volume}:/data" "$@" "${IMAGE}" > /dev/null
    track_container "${name}"
    return 0
}

# host_settle CONTAINER: agent_settle, and real-time file integrity monitoring running again
host_settle() {
    local c="$1"
    agent_settle "${c}"
    wait_for 60 "real-time file integrity monitoring runs again" \
        container_log_has_at_least "${c}" "Real-time file integrity monitoring started" 2
    return 0
}

# manager_api PATH -> the manager API's answer for PATH (for example /syscollector/002/os)
manager_api() {
    local path="$1"
    docker exec "${MANAGER}" bash -c "
        token=\$(curl -sk -u wazuh:wazuh -X POST 'https://localhost:55000/security/user/authenticate?raw=true')
        curl -sk -H \"Authorization: Bearer \${token}\" 'https://localhost:55000${path}'"
    return
}

# sca_checks AGENT-ID -> "ID RESULT" of every check of the app's policy, as the manager has them
sca_checks() {
    local id="$1"
    manager_api "/sca/${id}/checks/home_assistant_os?limit=100" | jq -r '.data.affected_items[]? | "\(.id) \(.result)"' | sort
    return 0
}

# sca_result AGENT-ID CHECK-ID -> the manager's result for that check
sca_result() {
    local id="$1" check="$2"
    sca_checks "${id}" | awk -v check="${check}" '$1 == check {print $2}'
    return 0
}

# sca_has_all_results AGENT-ID: the manager has the result of all 8 checks (a predicate for wait_for)
sca_has_all_results() {
    local id="$1"
    [[ "$(sca_checks "${id}" | wc -l)" -eq 8 ]]
    return
}

# manager_agent_ip NAME -> the address the manager has recorded for the agent ("null" until it has one)
manager_agent_ip() {
    local name="$1"
    manager_item "/agents?q=name=${name}&select=ip" '.ip'
    return
}

# manager_knows_agent_ip NAME: the manager has an address for the agent (a predicate for wait_for). The agent tells it
# with its keep-alives, and leaves it out of a keep-alive when it cannot read its own address yet, until the next
# refresh (client-agent/notify.c), so a check made right after the agent (re)started can find none.
manager_knows_agent_ip() {
    local ip
    ip="$(manager_agent_ip "$1")"
    [[ -n "${ip}" && "${ip}" != null && "${ip}" != any ]]
    return
}

# manager_host_inventory_ready NAME ID: all the host fields asserted by scenario_host have arrived
manager_host_inventory_ready() {
    local name="$1" id="$2" agent agent_ip agent_os os hostname cpu
    local host_processes manager_processes port_process accounts
    agent="$(manager_api "/agents?q=name=${name}")"
    agent_ip="$(jq -r '.data.affected_items[0].ip // empty' <<< "${agent}")"
    agent_os="$(jq -r '.data.affected_items[0].os.name // empty' <<< "${agent}")"
        os="$(manager_item "/syscollector/${id}/os" '.os.name + " " + .os.version + " (" + .os.platform + ")"')"
    hostname="$(manager_item "/syscollector/${id}/os" '.hostname')"
    cpu="$(manager_item "/syscollector/${id}/hardware" '.cpu.name')"
    host_processes="$(manager_api "/syscollector/${id}/processes?search=perl&limit=1" | jq -r '.data.total_affected_items // 0')"
    manager_processes="$(manager_api "/syscollector/${id}/processes?search=wazuh-analysisd&limit=1" | jq -r '.data.total_affected_items // 0')"
    port_process="$(manager_api "/syscollector/${id}/ports?search=perl" | jq -r '([.data.affected_items[]? | select(.local.port == 4242) | .process] | first) // empty')"
    accounts="$(manager_api "/syscollector/${id}/users?limit=500" | jq -r '[.data.affected_items[].user.name] | join(" ")')"

    [[ -n "${agent_ip}" && "${agent_ip}" != any && "${agent_os}" == "${HOST_OS_NAME}" \
        && "${os}" == "${HOST_OS_NAME} ${HOST_OS_VERSION} (haos)" && "${hostname}" == "${HOST_HOSTNAME}" \
        && -n "${cpu}" && "${cpu}" != null && "${cpu}" != "-" \
        && "${host_processes}" =~ ^[0-9]+$ && "${host_processes}" -ge 1 \
        && "${manager_processes}" =~ ^[0-9]+$ && "${manager_processes}" -ge 1 \
        && "${port_process}" == perl && " ${accounts} " == *" root "* && " ${accounts} " == *" wazuh "* ]]
    return
}

# manager_item PATH JQ-FILTER -> JQ-FILTER applied to the first item of the manager API's answer
manager_item() {
    local path="$1" filter="$2"
    manager_api "${path}" | jq -r ".data.affected_items[0] | ${filter}"
    return
}

check_equal() {
    local description="$1" actual="$2" expected="$3"
    if [[ "${actual}" == "${expected}" ]]; then
        pass "${description}"
    else
        fail "${description} (expected '${expected}', got '${actual}')"
    fi
    return 0
}

check_different() {
    local description="$1" actual="$2" other="$3"
    if [[ -n "${actual}" && "${actual}" != "null" && "${actual}" != "${other}" ]]; then
        pass "${description}"
    else
        fail "${description} (got '${actual}', which must be set and differ from '${other}')"
    fi
    return 0
}

# apparmor_available -> succeeds when AppArmor is enforced on this machine and profiles can be loaded
# (GitHub's Ubuntu runners; not a development machine whose kernel has it switched off).
apparmor_available() {
    [[ "$(cat /sys/module/apparmor/parameters/enabled 2> /dev/null)" == Y ]] \
        && command -v apparmor_parser > /dev/null && sudo -n true 2> /dev/null
    return
}

# apparmor_log PROFILE -> the lines in which that profile was denied something. Where the kernel
# writes them depends on the machine: the kernel's ring buffer, the journal (systemd's journald takes over
# auditing when it starts, so on Ubuntu they are only there), or auditd's own file.
apparmor_log() {
    local profile="$1"
    {
        sudo -n dmesg 2> /dev/null
        sudo -n journalctl -b --no-pager -q -o cat _TRANSPORT=audit _TRANSPORT=kernel 2> /dev/null
        sudo -n cat /var/log/audit/audit.log 2> /dev/null
    } | grep "apparmor=\"DENIED\".*profile=\"${profile}\"" || true
    return 0
}

# apparmor_denials PROFILE -> how many denials that is. The same record is in the ring buffer and in
# the journal, so they are counted by their audit serial, "audit(<time>:<serial>)", once each.
apparmor_denials() {
    local profile="$1" serials
    serials="$(apparmor_log "${profile}" | grep -o 'audit([0-9.]*:[0-9]*)' | sort -u || true)"
    if [[ -z "${serials}" ]]; then
        echo 0
    else
        wc -l <<< "${serials}"
    fi
    return 0
}

# apparmor_sample -> what the machine's logs say about AppArmor at all, for when a check fails
apparmor_sample() {
    {
        sudo -n dmesg 2> /dev/null
        sudo -n journalctl -b --no-pager -q -o cat _TRANSPORT=audit _TRANSPORT=kernel 2> /dev/null
    } | grep -i apparmor | tail -n 6 | sed 's/^/    | /' || true
    return 0
}

# manager_alert_count_for AGENT TEXT -> how many alerts of that agent contain TEXT (the manager is shared
# by every scenario, so a count over all alerts also counts what the others caused)
manager_alert_count_for() {
    local agent="$1" text="$2"
    docker exec "${MANAGER}" bash -c \
        "grep -F -- '\"name\":\"${agent}\"' /var/ossec/logs/alerts/alerts.json | grep -cF -- '${text}' || true"
    return 0
}
