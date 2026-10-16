#!/usr/bin/env bash
# Host helper tests: the logic that decides whether the agent can run against the Home Assistant OS
# host, where that host keeps the app's folders, and what its CPU is called. All of it runs in the
# app image, so what is tested is what ships.
#
#   IMAGE=ha-wazuh-agent:test tests/host/run.sh
#
# tests/fixtures/host/hostpath/NAME.{want,tables,expect}   a path in the container, the pair of mount
#                                                          tables (NAME.self / NAME.host) to match, and
#                                                          the path expected on the host (empty: none)
# tests/fixtures/host/cpuname/NAME.{cpuinfo,expect}        a /proc/cpuinfo and the CPU name expected from
#                                                          it (empty: it already has one). NAME.board
#                                                          and NAME.arch are optional inputs.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$(cd "${HERE}/../fixtures/host" && pwd)"
IMAGE="${IMAGE:-ha-wazuh-agent:test}"
LIB=/usr/local/lib/wazuh-ha

PASSED=0
FAILED=0
pass() {
    PASSED=$((PASSED + 1))
    printf '  \033[32mPASS\033[0m %s\n' "$*"
    return 0
}
fail() {
    FAILED=$((FAILED + 1))
    printf '  \033[31mFAIL\033[0m %s\n' "$*"
    return 0
}

# first_line FILE -> the file's first line, or nothing if the file does not exist
first_line() {
    local file="$1" line=""
    [[ -f "${file}" ]] && IFS= read -r line < "${file}"
    printf '%s' "${line}"
    return 0
}

# Where the container's path is on the host, by matching the two mount tables of a fixture.
check_hostpath() {
    local name="$1" tables want expect out rc
    tables="$(first_line "${FIXTURES}/hostpath/${name}.tables")"
    want="$(first_line "${FIXTURES}/hostpath/${name}.want")"
    expect="$(first_line "${FIXTURES}/hostpath/${name}.expect")"
    out="$(docker run --rm --entrypoint awk -v "${FIXTURES}:/f:ro" "${IMAGE}" -v "want=${want}" \
        -f "${LIB}/hostpath.awk" "/f/hostpath/${tables}.self" "/f/hostpath/${tables}.host" 2>&1)"
    rc=$?
    if [[ -z "${expect}" ]]; then
        [[ "${rc}" -eq 1 && -z "${out}" ]] && pass "${name}: ${want} has no counterpart on the host" \
            || fail "${name}: expected no result and status 1, got status ${rc}: ${out}"
    else
        [[ "${rc}" -eq 0 && "${out}" == "${expect}" ]] && pass "${name}: ${want} is ${expect} on the host" \
            || fail "${name}: expected ${expect}, got status ${rc}: ${out}"
    fi
    return 0
}

# What the CPU is called, from a /proc/cpuinfo the way an ARM kernel writes it.
check_cpuname() {
    local name="$1" board arch expect out
    board="$(first_line "${FIXTURES}/cpuname/${name}.board")"
    arch="$(first_line "${FIXTURES}/cpuname/${name}.arch")"
    expect="$(first_line "${FIXTURES}/cpuname/${name}.expect")"
    out="$(docker run --rm --entrypoint awk -v "${FIXTURES}:/f:ro" "${IMAGE}" -v "board=${board}" \
        -v "arch=${arch:-aarch64}" -f "${LIB}/cpuname.awk" "/f/cpuname/${name}.cpuinfo" 2>&1)"
    if [[ "${out}" == "${expect}" ]]; then
        pass "${name}: ${expect:-already named, nothing to add}"
    else
        fail "${name}: expected '${expect}', got '${out}'"
    fi
    return 0
}

# check_facts NAME OPTIONS-FILE JQ-TEST... [-- docker run options...]
# Runs `wazuh-ha-host facts` in the image and checks the answer against each jq test.
check_facts() {
    local name="$1" options="$2" out arg test after_separator=0
    shift 2
    local tests=() docker_args=()
    for arg in "$@"; do
        if [[ "${after_separator}" -eq 1 ]]; then
            docker_args+=("${arg}")
        elif [[ "${arg}" == "--" ]]; then
            after_separator=1
        else
            tests+=("${arg}")
        fi
    done
    out="$(docker run --rm --entrypoint wazuh-ha-host -v "${FIXTURES}:/f:ro" -e "OPTIONS_FILE=/f/${options}" \
        "${docker_args[@]}" "${IMAGE}" facts 2>&1)"
    for test in "${tests[@]}"; do
        if jq -e "${test}" <<< "${out}" > /dev/null 2>&1; then
            pass "${name}: ${test}"
        else
            fail "${name}: ${test} does not hold of ${out}"
        fi
    done
    return 0
}

printf '\n\033[1m==> host helper tests against %s\033[0m\n' "${IMAGE}"

printf '\n\033[1mwhere the host keeps the app'"'"'s folders\033[0m\n'
for want_file in "${FIXTURES}"/hostpath/*.want; do
    check_hostpath "$(basename "${want_file}" .want)"
done

printf '\n\033[1mwhat the CPU is called\033[0m\n'
for cpu_file in "${FIXTURES}"/cpuname/*.cpuinfo; do
    check_cpuname "$(basename "${cpu_file}" .cpuinfo)"
done

printf '\n\033[1mwhether the host can be reached\033[0m\n'
# The default privileges of a container: no SYS_ADMIN, no SYS_PTRACE.
check_facts "default privileges" options-default.json \
    '.requested == "host" and .mode == "unavailable" and .available == false' \
    '.reason == "missing_capabilities"' \
    '(.message | contains("SYS_ADMIN") and contains("SYS_PTRACE"))' \
    '.mounts == {}'
# What Protection mode on looks like from inside: the capabilities are granted (config.yaml declares
# them) but the host's process namespace is not shared, so PID 1 is this container's own init.
check_facts "protected app" options-default.json \
    '.requested == "host" and .mode == "unavailable" and .reason == "no_host_pid"' \
    '(.message | contains("Protection mode"))' \
    -- --cap-add SYS_ADMIN --cap-add SYS_PTRACE
# Monitoring the container is a choice that needs nothing from the host.
check_facts "monitor_host off" options-container.json \
    '.requested == "container" and .mode == "container" and .available == true and .reason == ""' \
    '.mounts == {}'

printf '\n\033[1m%s passed, %s failed\033[0m\n' "${PASSED}" "${FAILED}"
[[ "${FAILED}" -eq 0 ]]
