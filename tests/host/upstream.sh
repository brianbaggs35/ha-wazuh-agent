#!/usr/bin/env bash
# Is Home Assistant still started the way the app looks for it?
#
#   tests/host/upstream.sh
#
# The app finds Home Assistant Core and the Supervisor on the device by the command line of their processes
# (`wazuh-ha-host python-pid`), which the run scripts of their containers decide. That is not the app's to
# decide, and it changed once without notice (Core 2026.9 added -P to it), which emptied the package
# inventory of app version 1.0.3 without a single error. This fetches the run scripts as they are on each
# project's main branch and in its latest release, takes the `exec` line that starts the program, and checks
# that the app recognises the process that line starts.
#
# It needs GitHub. A file it cannot fetch is a warning and not a failure (exit 0): a change upstream is what
# this is for, a flaky network is not. A run script that no longer ends in `exec python3 ...` is a failure:
# the app has to be taught how to recognise the new one.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${HERE}/../../wazuh_agent/rootfs/usr/local/bin/wazuh-ha-host"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

PASSED=0
FAILED=0
SKIPPED=0
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
skip() {
    SKIPPED=$((SKIPPED + 1))
    printf '  \033[33mSKIP\033[0m %s\n' "$*"
    return 0
}

# github_get URL -> the body, retrying a few times; uses GITHUB_TOKEN for the API when there is one
github_get() {
    local url="$1"
    local -a auth=()
    [[ -n "${GITHUB_TOKEN:-}" && "${url}" == https://api.github.com/* ]] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    curl -fsSL --retry 3 --retry-delay 5 --max-time 30 "${auth[@]}" "${url}"
    return
}

# check_run_script REPO PATH REF MODULE: the run script of a container, at REF, starts a process the app recognises as MODULE
check_run_script() {
    local repo="$1" path="$2" ref="$3" module="$4" label script line proc
    label="${repo}@${ref}"
    if ! script="$(github_get "https://raw.githubusercontent.com/${repo}/${ref}/${path}")"; then
        skip "${label}: could not fetch ${path}"
        return 0
    fi
    # The line that replaces the shell by the program: the last one, as the run scripts end with it.
    line="$(grep -E '^exec +python3? ' <<< "${script}" | tail -n 1)"
    if [[ -z "${line}" ]]; then
        fail "${label}: ${path} no longer ends in 'exec python3 ...'; the app has to learn how the program is started now"
        return 0
    fi
    if [[ "${line}" == *[\$\"\'\`\\]* ]]; then
        fail "${label}: the line '${line}' uses quotes or variables; this check needs a person to read it"
        return 0
    fi
    # The process that line starts has the words after `exec` as its command line, separated by NUL bytes.
    proc="${WORK}/${repo//\//_}-${ref//\//_}"
    mkdir -p "${proc}/4242"
    # shellcheck disable=SC2086  # the words of the line are meant to be split
    printf '%s\0' ${line#exec } > "${proc}/4242/cmdline"
    if [[ "$(WAZUH_HA_PROC="${proc}" bash "${HOST}" python-pid "${module}")" == 4242 ]]; then
        pass "${label}: '${line}' is recognised as ${module}"
    else
        fail "${label}: '${line}' is not recognised as ${module}; the app would find nothing of it (wazuh-ha-host, python_module_pid)"
    fi
    return 0
}

# check_project REPO DEFAULT-BRANCH PATH MODULE: on the default branch and in the latest release
check_project() {
    local repo="$1" branch="$2" path="$3" module="$4" tag
    check_run_script "${repo}" "${path}" "${branch}" "${module}"
    if tag="$(github_get "https://api.github.com/repos/${repo}/releases/latest" | jq -r '.tag_name // empty' 2> /dev/null)" && [[ -n "${tag}" ]]; then
        check_run_script "${repo}" "${path}" "${tag}" "${module}"
    else
        skip "${repo}: could not read the latest release"
    fi
    return 0
}

printf '\n\033[1m==> Home Assistant is still started the way the app recognises it\033[0m\n'
check_project home-assistant/core dev rootfs/etc/services.d/home-assistant/run homeassistant
check_project home-assistant/supervisor main rootfs/etc/services.d/supervisor/run supervisor

printf '\n\033[1m%s passed, %s failed, %s skipped\033[0m\n' "${PASSED}" "${FAILED}" "${SKIPPED}"
[[ "${PASSED}" -gt 0 || "${SKIPPED}" -gt 0 ]] && [[ "${FAILED}" -eq 0 ]]
