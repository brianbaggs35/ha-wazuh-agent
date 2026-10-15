#!/usr/bin/env bash
# Runs the unit tests of every language in this repository and enforces 100% coverage of each.
#
#   scripts/ci/coverage.sh
#
# Needs: Docker, Python 3 with coverage.py (python3 -m pip install coverage), PyYAML not required.
#   Python  scripts/                       -> coverage.xml
#   Go      wazuh_agent/ui/server          -> coverage-go/coverage.out
#   Web     wazuh_agent/ui/web             -> wazuh_agent/ui/web/coverage/lcov.info
# These are the reports the SonarQube Cloud scan in CI reads (see sonar-project.properties).
#
# Go and Node run in the same pinned builder images the Dockerfile uses (the pins are read from
# it, so there is nothing to keep in step), as the current user, so no file ends up owned by root.
#
# Shell and jq (the app's start-up code) cannot be measured by these tools; the render tests and the
# end-to-end tests cover them instead. See CONTRIBUTING.md.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dockerfile="${root}/wazuh_agent/Dockerfile"
go_image="$(sed -n 's/^FROM \(golang:[^ ]*\) AS ui-server$/\1/p' "${dockerfile}")"
node_image="$(sed -n 's/^FROM \(node:[^ ]*\) AS ui-web$/\1/p' "${dockerfile}")"
python_bin="${PYTHON:-python3}"
user="$(id -u):$(id -g)"

[[ -n "${go_image}" && -n "${node_image}" ]] || { echo "could not read the builder images from the Dockerfile" >&2; exit 1; }

step() {
    printf '\n\033[1m==> %s\033[0m\n' "$1"
    return 0
}

step "Python: scripts/ (lines and branches, floor set in .coveragerc)"
cd "${root}"
"${python_bin}" -m coverage run -m unittest discover -s tests/scripts
"${python_bin}" -m coverage report
"${python_bin}" -m coverage xml -o coverage.xml
rm -f .coverage

step "Go: wazuh_agent/ui/server (${go_image%%@*})"
rm -rf "${root}/coverage-go"
mkdir -p "${root}/coverage-go"
docker run --rm --user "${user}" -e HOME=/tmp -e GOCACHE=/tmp/go-cache \
    -v "${root}/wazuh_agent/ui/server:/src" -v "${root}/coverage-go:/out" -w /src "${go_image}" \
    sh -euc '
        unformatted="$(gofmt -l .)"
        [ -z "${unformatted}" ] || { echo "gofmt needed on: ${unformatted}"; exit 1; }
        go vet ./...
        go test -race -count=1 -coverprofile=/out/coverage.out ./...
        go tool cover -func=/out/coverage.out | tail -n 1
        go tool cover -func=/out/coverage.out | awk "/^total:/ { exit (\$3 == \"100.0%\") ? 0 : 1 }" \
            || { echo "Go coverage is below 100%"; exit 1; }
    '
# Sonar maps coverage by repository-relative path; the profile uses the module's import path.
sed -i 's#^github.com/brianbaggs35/ha-wazuh-agent/ui/server/#wazuh_agent/ui/server/#' "${root}/coverage-go/coverage.out"

step "Web: wazuh_agent/ui/web (${node_image%%@*})"
docker run --rm --user "${user}" -e HOME=/tmp -v "${root}/wazuh_agent/ui/web:/w" -w /w "${node_image}" \
    sh -euc '
        npm ci --ignore-scripts --no-audit --no-fund
        npm run lint
        npm run format:check
        npm run typecheck
        npx vitest run --coverage
    '

# Sonar maps coverage by repository-relative path; the report's paths are relative to the web project.
sed -i -E 's#^SF:(\./)?(w/)?src/#SF:wazuh_agent/ui/web/src/#' "${root}/wazuh_agent/ui/web/coverage/lcov.info"

step "Every language is at 100%"
