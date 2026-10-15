#!/usr/bin/env bash
# Render tests: every fixture is rendered inside the app image and checked by Wazuh itself.
#
#   IMAGE=ha-wazuh-agent:test tests/render/run.sh
#
# tests/fixtures/options/ok-*.json   must render, pass every daemon's -t with no
#                                    warnings, and satisfy the has:/no: lines in the
#                                    matching .expect file
# tests/fixtures/options/bad-*.json  must be refused (exit 2) with the messages listed
#                                    as has: lines in the matching .expect file
# NAME.info.json next to a fixture replaces the default runtime info for it.
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

# render NAME -> splits the container's output into ${WORK}/NAME/{rc,stderr,ossec,lio,daemons}
render() {
    local name="$1" info="info.json" dir
    dir="${WORK}/${name}"
    [[ -f "${FIXTURES}/options/${name}.info.json" ]] && info="options/${name}.info.json"
    mkdir -p "${dir}"
    docker run --rm --entrypoint bash \
        -v "${FIXTURES}:/fixtures:ro" -v "${HERE}/in-container.sh:/in-container.sh:ro" \
        "${IMAGE}" /in-container.sh "/fixtures/options/${name}.json" "/fixtures/${info}" > "${dir}/raw" 2>&1
    awk -v d="${dir}" '
        /^@@@RC /     { print $2 > (d "/rc"); next }
        /^@@@STDERR$/ { out = d "/stderr"; next }
        /^@@@OSSEC$/  { out = d "/ossec"; next }
        /^@@@LIO$/    { out = d "/lio"; next }
        /^@@@DAEMONS$/{ out = d "/daemons"; next }
        out           { print > out }' "${dir}/raw"
    touch "${dir}/stderr" "${dir}/ossec" "${dir}/lio" "${dir}/daemons"
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
            *) fail "${name}: unknown expectation '${kind}' in ${expect} (use has: or no:)" ;;
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
    if grep -E 'rc=[1-9]|complaint:' "${dir}/daemons" > "${dir}/problems"; then
        fail "${name}: Wazuh objected to the generated configuration"
        sed 's/^/    | /' "${dir}/problems"
    else
        pass "${name}: every Wazuh daemon accepts it (-t) without warnings"
    fi
    check_expectations "${name}" "${dir}/ossec"
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
# would behave differently depending on whether the Supervisor filled it in.
printf '\n\033[1mdefaults drift\033[0m\n'
if python3 -I "${HERE}/../config/defaults_json.py" "${HERE}/../../wazuh_agent/config.yaml" > "${FIXTURES}/options/zz-defaults.json" 2> "${WORK}/defaults.err"; then
    render ok-minimal
    render zz-defaults
    if diff -u "${WORK}/ok-minimal/ossec" "${WORK}/zz-defaults/ossec" > "${WORK}/drift.diff" \
        && diff -u "${WORK}/ok-minimal/lio" "${WORK}/zz-defaults/lio" >> "${WORK}/drift.diff"; then
        pass "options left unset render exactly like the config.yaml defaults"
    else
        fail "the renderer's built-in defaults differ from config.yaml"
        sed 's/^/    | /' "${WORK}/drift.diff" | head -30
    fi
else
    fail "could not read the defaults from config.yaml"
    sed 's/^/    | /' "${WORK}/defaults.err"
fi
rm -f "${FIXTURES}/options/zz-defaults.json"

printf '\n\033[1m%s passed, %s failed\033[0m\n' "${PASSED}" "${FAILED}"
[[ "${FAILED}" -eq 0 ]]
