#!/usr/bin/env bash
# Runs inside the app image (the Wazuh binaries and the renderer live there).
# Renders one options file, then lets every Wazuh daemon check the result with -t.
#
# Output is a simple section stream that run.sh splits apart:
#   @@@RC <n> / @@@STDERR / @@@OSSEC / @@@LIO / @@@FILES / @@@DAEMONS
set -uo pipefail

options="$1"
info="$2"
out="$(mktemp -d)"

stderr="$(wazuh-ha-render --options "${options}" --info "${info}" --outdir "${out}" 2>&1 > /dev/null)"
rc=$?
echo "@@@RC ${rc}"
echo "@@@STDERR"
printf '%s\n' "${stderr}"
[[ "${rc}" -eq 0 ]] || exit 0

echo "@@@OSSEC"
cat "${out}/ossec.conf"
echo "@@@LIO"
cat "${out}/local_internal_options.conf"
# What else the renderer wrote (the app's own SCA policy, when the configuration lists it).
echo "@@@FILES"
ls "${out}"

# The daemons read /var/ossec/etc/ossec.conf; at build time /var/ossec is a symlink
# to the (not yet existing) persistent volume, so give the test a real copy.
rm -f /var/ossec
cp -a /var/ossec.dist /var/ossec
cp "${out}/ossec.conf" /var/ossec/etc/ossec.conf
cp "${out}/local_internal_options.conf" /var/ossec/etc/local_internal_options.conf
# wazuh-ha-init puts the policy here; without it Wazuh's check would say it cannot find the file.
if [[ -f "${out}/home_assistant_os.yml" ]]; then
    mkdir -p /var/ossec/ruleset/ha
    cp "${out}/home_assistant_os.yml" /var/ossec/ruleset/ha/home_assistant_os.yml
fi

echo "@@@DAEMONS"
for daemon in wazuh-agentd wazuh-execd wazuh-logcollector wazuh-modulesd wazuh-syscheckd; do
    output="$("/var/ossec/bin/${daemon}" -t 2>&1)"
    echo "${daemon} rc=$?"
    # Anything Wazuh complains about is a defect in the generated configuration.
    grep -E ' (WARNING|ERROR|CRITICAL):' <<< "${output}" | sed "s/^/${daemon} complaint: /"
done
exit 0
