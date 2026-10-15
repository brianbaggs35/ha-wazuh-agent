# Contributing

## Layout

```text
wazuh_agent/            the Home Assistant app (this is what the Supervisor sees)
  config.yaml           options, schema and the privileges the app asks for
  Dockerfile            Debian base + the Wazuh agent from the official apt repository
  apparmor.txt          the app's AppArmor profile
  translations/en.yaml  the text shown for every option in the UI
  DOCS.md README.md CHANGELOG.md
  rootfs/               what is copied into the image
    etc/s6-overlay/s6-rc.d/   the init step and the agent service
    usr/local/lib/wazuh-ha/   jq programs: validation, render context, and the writers of ossec.conf
    usr/local/bin/            the renderer and the health check
tests/
  config/    static checks: options vs translations, security rating, versions
  render/    renders fixtures inside the image; every Wazuh daemon checks the result
  e2e/       the image against a real Wazuh manager
  scripts/   unit tests for scripts/wazuh_update.py
scripts/     maintenance scripts
.github/     CI, release and the weekly Wazuh version watch
```

## Running the tests

You need Docker and Python 3 with PyYAML.

```bash
# static checks (no Docker)
python3 -I tests/config/check_config.py
python3 -I -m unittest discover -s tests/scripts

# build the image once, then:
docker build -t ha-wazuh-agent:test wazuh_agent
IMAGE=ha-wazuh-agent:test tests/render/run.sh        # about a minute
IMAGE=ha-wazuh-agent:test tests/e2e/run.sh            # about 15 minutes; starts a real Wazuh manager
IMAGE=ha-wazuh-agent:test tests/e2e/run.sh enroll     # a single scenario
```

`MANAGER_VERSION=4.14.8` runs the end-to-end tests against a different manager version.
`E2E_KEEP=1` leaves the containers behind for debugging.

## Rules this project keeps

- **The security rating stays at 8.** `tests/config/check_config.py` recomputes the Supervisor's
  rating from `config.yaml` and fails if it drops, or if the app starts asking for host network,
  ports, capabilities, full access, a host PID namespace or the Docker API. Changing that is a
  design decision: change `MINIMUM_RATING` in the same pull request and explain why.
- **Every option has a translation and a default** that satisfies its own schema (checked).
- **The renderer's built-in defaults equal `config.yaml`** (checked by the render tests).
- **Values go into `ossec.conf` exactly as typed.** Wazuh's configuration reader does not decode
  XML entities and treats `\` and `<` specially, so the validator refuses what it cannot represent.
  Do not HTML-escape values in the renderer.
- **A new feature needs a test that proves it works against a real manager**, not only that the
  generated configuration looks right.

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
