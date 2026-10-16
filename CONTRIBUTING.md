# Contributing

## Layout

```text
wazuh_agent/            the Home Assistant app (this is what the Supervisor sees)
  config.yaml           options, schema and the privileges the app asks for
  Dockerfile            Debian base + the Wazuh agent from the official apt repository
  apparmor.txt          the app's AppArmor profile
  translations/en.yaml  the text shown for every option in the UI
  DOCS.md README.md CHANGELOG.md
  ui/server/            the status page's server (Go, standard library only)
  ui/web/               the status page (Vue 3 + Vuetify, TypeScript)
  rootfs/               what is copied into the image
    usr/local/bin/            wazuh-ha-entrypoint (the app's supervisor), -init, -host (runs the agent
                              in the Home Assistant OS host's file system), the renderer, the health check
    usr/local/lib/wazuh-ha/   jq programs (validation, render context, the writers of ossec.conf), the awk
                              programs that find the host's paths and name an ARM CPU, hostns-start (runs
                              inside the host's mount namespace) and the restart.sh that replaces Wazuh's
tests/
  config/    static checks: options vs translations, the reviewed host access and its security rating, versions
  render/    renders fixtures inside the image; every Wazuh daemon checks the result
  host/      unit tests of the host helpers (mount-table matching, CPU naming, reachability) in the image
  e2e/       the image against a real Wazuh manager, in a container and against a stand-in for the device
  scripts/   unit tests for scripts/wazuh_update.py
scripts/ci/  coverage.sh: every language's unit tests, with a 100% floor
scripts/     maintenance scripts
.github/     CI, release and the weekly Wazuh version watch
```

## Running the tests

You need Docker and Python 3 with PyYAML.

```bash
# static checks (no Docker)
python3 -I tests/config/check_config.py
python3 -I -m unittest discover -s tests/scripts
# unit tests of every language (Python, Go, web) with the 100% coverage floor CI enforces;
# needs Docker (Go and Node run in the pinned builder images) and coverage.py
python3 -m pip install coverage && scripts/ci/coverage.sh

# build the image once, then:
docker build -t ha-wazuh-agent:test wazuh_agent
IMAGE=ha-wazuh-agent:test tests/render/run.sh        # about a minute
IMAGE=ha-wazuh-agent:test tests/host/run.sh          # about a minute
IMAGE=ha-wazuh-agent:test tests/e2e/run.sh            # about 25 minutes; starts a real Wazuh manager
IMAGE=ha-wazuh-agent:test tests/e2e/run.sh enroll     # a single scenario
IMAGE=ha-wazuh-agent:test tests/e2e/run.sh host       # the agent against a stand-in for the device
IMAGE=ha-wazuh-agent:test tests/e2e/run.sh host_apparmor  # the same under the app's AppArmor profile; needs sudo and an AppArmor kernel, skips itself otherwise
```

`MANAGER_VERSION=4.14.8` runs the end-to-end tests against a different manager version.
`E2E_KEEP=1` leaves the containers behind for debugging.

## Repository settings the workflows rely on

| Setting | Why |
| --- | --- |
| **Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"** | The weekly *Wazuh version watch* opens its pull request with the default token. Without this it fails at that step. |
| Secret `SONAR_TOKEN` | The SonarQube Cloud scan in CI (project `brianbaggs35_ha-wazuh-agent`, configured in `sonar-project.properties`). Pull requests from forks cannot read it, so the scan is skipped for them. In SonarQube Cloud, **Automatic Analysis must be off** for this project: it conflicts with the CI-based scan. |
| Secret `WAZUH_UPDATE_TOKEN` (optional) | A fine-grained token with *contents* and *pull requests* write access. Pull requests opened with the default token do not start CI; with this token they do. |
| **Branch protection on `master`**: require a pull request and the status check **CI passed** | `CI passed` is the single job that is green only when lint, tests and scans all are. |
| **Code scanning** enabled | The Trivy results are uploaded as SARIF; the upload is skipped quietly if it is off. |
| Package visibility of `ghcr.io/<owner>/wazuh_agent` set to **public** (after the first release) | Home Assistant pulls the image anonymously. |

## Rules this project keeps

- **The app is the agent of the Home Assistant OS device, and asks for exactly the access that takes.**
  `tests/config/check_config.py` recomputes the Supervisor's rating from `config.yaml` (3 today) and
  fails if it changes, or if the app asks for anything beyond `host_pid`, `host_network`, `host_uts` and
  the `SYS_PTRACE` and `SYS_ADMIN` capabilities (full access, the Docker API, ports, a higher
  Supervisor role). Adding to that list is a design decision: change the list and `MINIMUM_RATING`
  together in the pull request, explain why, and update the Security section of `DOCS.md`, which says
  what each permission is for.
- **Nothing in the app signals or trusts a process it has not checked.** The app shares the device's
  process namespace, so a PID is a PID on the whole device: the supervisor and the health check only
  act on a PID whose command line is a Wazuh daemon's.
- **Coverage stays at 100%** for Python, Go and the web code (`scripts/ci/coverage.sh`).
- **Every option has a translation and a default** that satisfies its own schema (checked).
- **The renderer's built-in defaults equal `config.yaml`** (checked by the render tests).
- **Values go into `ossec.conf` exactly as typed.** Wazuh's configuration reader does not decode
  XML entities and treats `\` and `<` specially, so the validator refuses what it cannot represent.
  Do not HTML-escape values in the renderer.
- **A new feature needs a test that proves it works against a real manager**, not only that the
  generated configuration looks right.

## Working on the status page

```bash
cd wazuh_agent/ui/web
npm ci && npm run dev          # http://127.0.0.1:5173, proxying /api to WAZUH_UI_URL
npm run coverage               # vitest; fails below 100%
```

The server is plain `go` (standard library only): `cd wazuh_agent/ui/server && go test -race ./...`
(Go 1.26 or newer; the image builds with the version pinned in the Dockerfile).

The page is read-only and unprivileged by design: the root-owned supervisor service in the app
publishes a few non-secret files, and the server only reads them. Keep it that way: no write
endpoints, and nothing the page serves may contain the agent key (an end-to-end test checks).

## Releasing

1. Update `version` in `wazuh_agent/config.yaml` and add an entry to `wazuh_agent/CHANGELOG.md`
   with the release date (`unreleased` is refused).
2. Merge to `master`.
3. Create a GitHub release whose tag is the version. The release workflow tests and scans the
   exact images, then publishes the multi-arch image and signs it.

Use the **Release** workflow's manual run as a rehearsal: it does everything except create the
multi-arch tags.

## Updating the Wazuh agent

A weekly workflow opens a pull request when Wazuh publishes a newer stable agent. To check by hand:

```bash
python3 -I scripts/wazuh_update.py check
```

Before releasing an update that changes Wazuh's minor version, upgrade the Wazuh manager: it must
not be older than the agent.
