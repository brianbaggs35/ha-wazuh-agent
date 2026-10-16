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
#   host_agent_start NAME DATA-VOLUME HOST [docker run options...]  start the app, in host mode
#   host_settle CONTAINER                                           wait out the agent's first restart
#   manager_api PATH                                                the manager API's answer (JSON)
#   check_equal / check_different DESCRIPTION ACTUAL EXPECTED       one assertion

HOST_IMAGE="${HOST_IMAGE:-debian:bookworm-slim}"
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
#   * a process listening on port 4242, for the inventory to find
host_start() {
    local name="$1" volume="$2"
    shift 2
    docker rm -f "${name}" > /dev/null 2>&1 || true
    docker run -d --name "${name}" --hostname "${HOST_HOSTNAME}" --network "${E2E_NET}" --pid=host \
        --cap-add SYS_ADMIN -v "${volume}:${HOST_DATA_PATH}" "$@" "${HOST_IMAGE}" bash -c '
        mount --make-rshared /
        mkdir -p /etc/ssh /root/.ssh /mnt/boot /mnt/data/supervisor/addons/local /run/systemd/system
        printf "%s\n" "NAME=\"Home Assistant OS\"" "VERSION=\"17.0\"" "ID=haos" "VERSION_ID=\"17.0\"" \
            "PRETTY_NAME=\"Home Assistant OS 17.0\"" > /etc/os-release
        echo "PermitRootLogin no" > /etc/ssh/sshd_config
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIe2e000000000000000000000000000000000000 e2e" > /root/.ssh/authorized_keys
        [ -z "${HOST_MACHINE_ID:-}" ] || echo "${HOST_MACHINE_ID}" > /etc/machine-id
        printf "#!/bin/sh\necho \"\$*\" >> /tmp/systemctl.log\nexit 5\n" > /usr/bin/systemctl
        chmod +x /usr/bin/systemctl
        perl -MIO::Socket::INET -e "my \$socket = IO::Socket::INET->new(Listen => 5, LocalPort => 4242, ReuseAddr => 1) or die; sleep" &
        touch /tmp/host-ready
        exec sleep infinity' > /dev/null
    track_container "${name}"
    wait_for 60 "the stand-in host is ready" docker exec "${name}" test -f /tmp/host-ready
    return
}

# host_agent_start NAME DATA-VOLUME HOST [docker run options...]
# The app, started the way Home Assistant starts it with host_network, host_pid, host_uts and the
# SYS_ADMIN and SYS_PTRACE capabilities, and Protection mode off: in the stand-in's network, in the
# host's process namespace, under Docker's init, with seccomp off (the Supervisor turns it off for
# every app).
host_agent_start() {
    local name="$1" volume="$2" host="$3" pid
    shift 3
    pid="$(docker inspect -f '{{.State.Pid}}' "${host}")"
    docker rm -f "${name}" > /dev/null 2>&1 || true
    docker run -d --init --name "${name}" --network "container:${host}" --pid=host \
        --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
        -e "WAZUH_HA_HOST_PID=${pid}" -e WAZUH_UI_ALLOW=0.0.0.0/0 \
        -v "${volume}:/data" "$@" "${IMAGE}" > /dev/null
    track_container "${name}"
    return 0
}

# container_log_count CONTAINER TEXT -> how many log lines contain TEXT
container_log_count() {
    local name="$1" text="$2" logs
    logs="$(docker logs "${name}" 2>&1)"
    grep -cF -- "${text}" <<< "${logs}" || true
    return 0
}

# container_log_has_at_least CONTAINER TEXT COUNT (a predicate for wait_for)
container_log_has_at_least() {
    local name="$1" text="$2" count="$3"
    [[ "$(container_log_count "${name}" "${text}")" -ge "${count}" ]]
    return
}

# host_settle CONTAINER
# The first time an agent connects, the manager sends it the group configuration and Wazuh asks for a
# restart. The app does that restart itself (a restart.sh that asked systemd would find none on the
# host), and events produced meanwhile are lost, so tests that inject events wait until it is over.
host_settle() {
    local c="$1"
    wait_for 120 "the agent is asked to restart after the first configuration" \
        container_log_has "${c}" "Wazuh asked for the agent to be restarted" || info "no restart request seen"
    wait_for 120 "the agent runs again" container_log_has_at_least "${c}" "Wazuh agent running:" 2
    wait_for 120 "the agent is connected again" docker exec "${c}" wazuh-ha-healthcheck
    wait_for 60 "real-time file integrity monitoring runs again" \
        container_log_has_at_least "${c}" "Real-time file integrity monitoring started" 2
    sleep 5
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

# apparmor_denials PROFILE -> how many lines of the kernel log say the profile denied something
apparmor_denials() {
    local profile="$1" log
    log="$(sudo -n dmesg 2> /dev/null)"
    grep -c "apparmor=\"DENIED\".*profile=\"${profile}\"" <<< "${log}" || true
    return 0
}
