#!/usr/bin/env bash
# Render tests: every fixture is rendered inside the app image and checked by Wazuh itself.
#
#   IMAGE=ha-wazuh-agent:test tests/render/run.sh
#
# tests/fixtures/options/ok-*.json   must render, pass every daemon's -t with no
#                                    warnings, and satisfy the has:/no: lines in the
#                                    matching .expect file. An "allow: TEXT" line names a
#                                    warning that is expected (and a "# ..." line is a comment).
# tests/fixtures/options/bad-*.json  must be refused (exit 2) with the messages listed
#                                    as has: lines in the matching .expect file
# An "in-sca: TEXT" line looks only inside the <sca> section (where <enabled> would be ambiguous).
# NAME.info.json next to a fixture replaces the default runtime info for it. The ok-host* fixtures
# describe the agent running in the Home Assistant OS host's file system (where the app's folders are
# at other paths), ok-host-unavailable one that cannot reach it.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$(cd "${HERE}/../fixtures" && pwd)"
IMAGE="${IMAGE:-ha-wazuh-agent:test}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

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

# render NAME [INFO [LABEL]] -> splits the container's output into ${WORK}/LABEL/{rc,stderr,ossec,lio,files,daemons}
# INFO is a runtime info file, relative to the fixtures; the default is NAME.info.json next to the
# fixture, or else info.json. LABEL (default NAME) names the output.
render() {
    local name="$1" info="${2:-}" label="${3:-$1}" dir
    dir="${WORK}/${label}"
    if [[ -z "${info}" ]]; then
        info="info.json"
        [[ -f "${FIXTURES}/options/${name}.info.json" ]] && info="options/${name}.info.json"
    fi
    mkdir -p "${dir}"
    docker run --rm --entrypoint bash \
        -v "${FIXTURES}:/fixtures:ro" -v "${HERE}/in-container.sh:/in-container.sh:ro" \
        "${IMAGE}" /in-container.sh "/fixtures/options/${name}.json" "/fixtures/${info}" > "${dir}/raw" 2>&1
    awk -v d="${dir}" '
        /^@@@RC /     { print $2 > (d "/rc"); next }
        /^@@@STDERR$/ { out = d "/stderr"; next }
        /^@@@OSSEC$/  { out = d "/ossec"; next }
        /^@@@LIO$/    { out = d "/lio"; next }
        /^@@@FILES$/  { out = d "/files"; next }
        /^@@@DAEMONS$/{ out = d "/daemons"; next }
        out           { print > out }' "${dir}/raw"
    touch "${dir}/stderr" "${dir}/ossec" "${dir}/lio" "${dir}/files" "${dir}/daemons"
    return 0
}

# filter_allowed NAME PROBLEMS-FILE: drops from the file the complaints the fixture says to expect
filter_allowed() {
    local name="$1" file="$2" expect line
    expect="${FIXTURES}/options/${name}.expect"
    [[ -f "${expect}" ]] || return 0
    while IFS= read -r line; do
        [[ "${line}" == "allow: "* ]] || continue
        grep -vF -- "${line#allow: }" "${file}" > "${file}.kept"
        mv "${file}.kept" "${file}"
    done < "${expect}"
    return 0
}

check_expectations() { # NAME FILE-TO-SEARCH
    local name="$1" file="$2" expect kind text
    expect="${FIXTURES}/options/${name}.expect"
    [[ -f "${expect}" ]] || return 0
    while IFS= read -r line; do
        kind="${line%%: *}"
        text="${line#*: }"
        case "${kind}" in
            has) grep -qF -- "${text}" "${file}" && pass "${name}: has ${text}" || fail "${name}: expected ${text}" ;;
            no) grep -qF -- "${text}" "${file}" && fail "${name}: must not contain ${text}" || pass "${name}: no ${text}" ;;
            in-sca)
                sed -n '/<sca>/,/<\/sca>/p' "${file}" > "${file}.sca"
                grep -qF -- "${text}" "${file}.sca" && pass "${name}: <sca> has ${text}" || fail "${name}: <sca> should have ${text}"
                ;;
            allow | "#"*) ;;
            *) fail "${name}: unknown expectation '${kind}' in ${expect} (use has:, no:, in-sca:, allow: or #)" ;;
        esac
    done < "${expect}"
    return 0
}

printf '\n\033[1m==> render tests against %s\033[0m\n' "${IMAGE}"

for fixture in "${FIXTURES}"/options/ok-*.json; do
    case "${fixture}" in
        *.info.json) continue ;;
        *) ;;
    esac
    name="$(basename "${fixture}" .json)"
    printf '\n\033[1m%s\033[0m\n' "${name}"
    render "${name}"
    dir="${WORK}/${name}"
    if [[ "$(cat "${dir}/rc")" != 0 ]]; then
        fail "${name}: rendering failed"
        sed 's/^/    | /' "${dir}/stderr" "${dir}/raw" | head -20
        continue
    fi
    pass "${name}: rendered"
    # A missing value would surface as a literal null (jq prints it) in the output.
    grep -qE '>null<|="null"|=null$' "${dir}/ossec" "${dir}/lio" && fail "${name}: a null leaked into the output" || pass "${name}: no null values in the output"
    # Every daemon accepted it and had no complaints.
    grep -E 'rc=[1-9]|complaint:' "${dir}/daemons" > "${dir}/problems"
    filter_allowed "${name}" "${dir}/problems"
    if [[ -s "${dir}/problems" ]]; then
        fail "${name}: Wazuh objected to the generated configuration"
        sed 's/^/    | /' "${dir}/problems"
    else
        pass "${name}: every Wazuh daemon accepts it (-t) without warnings"
    fi
    check_expectations "${name}" "${dir}/ossec"
    # The policy the configuration names and the policy file that is written are one decision: never one without the other.
    if grep -qF 'ruleset/ha/home_assistant_os.yml' "${dir}/ossec"; then
        grep -qx 'home_assistant_os.yml' "${dir}/files" \
            && pass "${name}: the app's SCA policy is named in ossec.conf and written" \
            || fail "${name}: ossec.conf names the app's SCA policy but it was not written"
    else
        grep -qx 'home_assistant_os.yml' "${dir}/files" \
            && fail "${name}: the app's SCA policy was written but ossec.conf does not name it" \
            || pass "${name}: no app SCA policy named, none written"
    fi
done

for fixture in "${FIXTURES}"/options/bad-*.json; do
    [[ -e "${fixture}" ]] || continue
    name="$(basename "${fixture}" .json)"
    printf '\n\033[1m%s\033[0m\n' "${name}"
    render "${name}"
    dir="${WORK}/${name}"
    [[ "$(cat "${dir}/rc")" == 2 ]] && pass "${name}: refused (exit 2)" || fail "${name}: expected exit 2, got $(cat "${dir}/rc")"
    check_expectations "${name}" "${dir}/stderr"
done

# The jq fallbacks must equal the defaults declared in config.yaml, or an option left unset
# would behave differently depending on whether the Supervisor filled it in. Checked for the agent
# in a container and for the agent on the host, which renders more (and from other options).
check_drift() { # LABEL FIXTURE INFO
    local label="$1" fixture="$2" info="$3"
    render "${fixture}" "${info}" "${label}-unset"
    render zz-defaults "${info}" "${label}-defaults"
    if diff -u "${WORK}/${label}-unset/ossec" "${WORK}/${label}-defaults/ossec" > "${WORK}/${label}.diff" \
        && diff -u "${WORK}/${label}-unset/lio" "${WORK}/${label}-defaults/lio" >> "${WORK}/${label}.diff" \
        && diff -u "${WORK}/${label}-unset/files" "${WORK}/${label}-defaults/files" >> "${WORK}/${label}.diff"; then
        pass "${label}: options left unset render exactly like the config.yaml defaults"
    else
        fail "${label}: the renderer's built-in defaults differ from config.yaml"
        sed 's/^/    | /' "${WORK}/${label}.diff" | head -30
    fi
    return 0
}

printf '\n\033[1mdefaults drift\033[0m\n'
if python3 -I "${HERE}/../config/defaults_json.py" "${HERE}/../../wazuh_agent/config.yaml" > "${FIXTURES}/options/zz-defaults.json" 2> "${WORK}/defaults.err"; then
    check_drift container ok-minimal info.json
    check_drift host ok-host-minimal options/ok-host-minimal.info.json
else
    fail "could not read the defaults from config.yaml"
    sed 's/^/    | /' "${WORK}/defaults.err"
fi
rm -f "${FIXTURES}/options/zz-defaults.json"

printf '\n\033[1m%s passed, %s failed\033[0m\n' "${PASSED}" "${FAILED}"
[[ "${FAILED}" -eq 0 ]]
