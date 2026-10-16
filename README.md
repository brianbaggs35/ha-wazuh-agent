# Wazuh Agent for Home Assistant

[![CI](https://github.com/brianbaggs35/ha-wazuh-agent/actions/workflows/ci.yaml/badge.svg)](https://github.com/brianbaggs35/ha-wazuh-agent/actions/workflows/ci.yaml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=brianbaggs35_ha-wazuh-agent&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=brianbaggs35_ha-wazuh-agent)

A [Home Assistant](https://www.home-assistant.io) app (formerly "add-on") that is the
[Wazuh](https://wazuh.com) agent of your Home Assistant OS device: installing it does what installing
the Wazuh agent on the device would do, which Home Assistant OS does not allow, and **enrolls the
device in your existing Wazuh manager**. The device itself is what is managed, scanned and monitored:
its address, operating system, processes, files and logs, not those of a container.

> **Protection mode must be off.** Reaching the device takes more access than a protected app has, so
> after installing, turn **Protection mode** off on the app's Info tab. The security rating Home
> Assistant shows is low because of this access, on purpose: see [Security](wazuh_agent/DOCS.md#security).

> **Testing.** The test suite runs the app against real Wazuh managers and a stand-in for the Home
> Assistant OS device (enrollment, persistence, journal, file integrity, and that what the manager
> records is the device's, not the container's), and CI runs it on amd64 and natively on arm64. The
> app's AppArmor profile is loaded into the runner's kernel and the agent runs under it. Home
> Assistant itself (the Supervisor, its handling of Protection mode, how it installs the profile,
> ingress) is not part of the automated tests.

[![Add this repository to your Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbrianbaggs35%2Fha-wazuh-agent)

## Install

1. Add this repository to Home Assistant: use the button above, or open **Settings → Apps → App
   store → ⋮ → Repositories** and add `https://github.com/brianbaggs35/ha-wazuh-agent`.
2. Install **Wazuh Agent**, open its **Info** tab and turn **Protection mode** off.
3. Set **Wazuh manager address** in its Configuration tab, and start it.
4. The device appears under **Agents** in the Wazuh dashboard, with its own address and operating system.

The full guide (ports, registration passwords, what is monitored, every option, troubleshooting)
is the app's [documentation](wazuh_agent/DOCS.md).

## What it does

- Enrolls with **just a manager address**; supports registration passwords, groups, certificate
  verification, failover managers and a fixed agent name.
- Runs the agent **on the device**: the dashboard shows the device's real address, host name,
  operating system, CPU (also on ARM, which Wazuh cannot name by itself), processes, listening ports,
  accounts and services.
- Reads the **host journal**: SSH logins, `sudo`, kernel warnings, Home Assistant Core (including
  failed web logins), the Supervisor and app errors.
- Watches the Home Assistant **configuration and certificates**, the device's `/etc` and binaries, the
  boot partition and root's SSH keys for changes, without ever sending the content of secrets.
- Runs **rootkit checks**, and configuration assessment with your own policies, against the device.
- Inventories the **Python packages Home Assistant Core runs on**, which is what Wazuh's vulnerability
  detection can match on a device with no package manager of its own.
- Labels every event with the Home Assistant OS, Core and Supervisor versions.
- A read-only **Wazuh Agent** status page in the Home Assistant sidebar: running or stopped,
  connected or not, registration, update availability, a connection test and the agent log.

## What it needs, and why the security rating is low

An app is a container, and a container cannot see the device it runs on. To be the agent of the
device, this app asks Home Assistant for the device's process namespace (`host_pid`, which Home
Assistant applies only while Protection mode is off), its network and host name, and the `SYS_PTRACE`
and `SYS_ADMIN` capabilities, and runs the agent's daemons inside the device's own file system. That
costs security rating (the Supervisor shows 3), and the documentation explains each permission and
what it is used for: [Security](wazuh_agent/DOCS.md#security). It still asks for no full access, no
Docker API, no published ports and no Supervisor role above the default, ships a custom AppArmor
profile, and `tests/config/check_config.py` guards that exact list in CI. Set `monitor_host` to
`false` to monitor only the app's own container instead.

## Updating the Wazuh agent

The agent is part of the image: updating it means releasing a new version of the app, which Home
Assistant then offers as a normal update. A weekly workflow opens a pull request when Wazuh
publishes a newer stable agent; the pull request goes through the full test suite before anything
is released. See the [changelog](wazuh_agent/CHANGELOG.md).

## How it is built and tested

| | |
| --- | --- |
| Base image | Home Assistant's Debian (trixie) base, pinned by digest. |
| Agent | Installed from Wazuh's official apt repository; the build fails if the repository's signing key differs from the pinned fingerprint. |
| Coverage | 100% of lines and branches for the Python, Go and web code, enforced in CI (`scripts/ci/coverage.sh`). Shell and jq cannot be measured by those tools; the render and end-to-end tests cover them. |
| Tests | Render tests (every Wazuh daemon checks the generated configuration), unit tests of the helpers that find the device's paths and name an ARM CPU, and end-to-end tests against the official `wazuh-manager` image: enrollment, persistence across restarts and updates, journal collection and filtering, file integrity, registration passwords, re-enrollment, and the agent running against a stand-in for the Home Assistant OS device (what the manager records is the device's, the real device is left untouched, and what happens when the device cannot be reached). |
| Architectures | `amd64` and `aarch64`, each built and tested on a native runner. |
| Scans | Trivy on the image (vulnerabilities, a gate on fixable HIGH and CRITICAL), configuration and secrets, plus an SBOM per release; SonarQube Cloud analysis of the code with its quality gate. |
| Releases | Published only after the exact images pass the tests and scans; the multi-arch image is signed with Sigstore and verified again from the registry. |

See [CONTRIBUTING.md](CONTRIBUTING.md) to run the tests yourself.

## Licence and trademarks

The code in this repository is [MIT licensed](LICENSE). The image bundles the Wazuh agent, which
is licensed under the GNU GPL v2 by Wazuh, Inc., and the Home Assistant base image; their licences
apply to those parts.

Wazuh is a trademark of Wazuh, Inc. This is an independent project, not affiliated with, endorsed by
or sponsored by Wazuh, Inc. The icon and logo in this repository are original artwork: Wazuh's
[trademark policy](https://wazuh.com/legal-resources/trademark-policy/) does not allow its logo in
another product's own logo without a written licence.
