# Wazuh Agent for Home Assistant

[![CI](https://github.com/brianbaggs35/ha-wazuh-agent/actions/workflows/ci.yaml/badge.svg)](https://github.com/brianbaggs35/ha-wazuh-agent/actions/workflows/ci.yaml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=brianbaggs35_ha-wazuh-agent&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=brianbaggs35_ha-wazuh-agent)

A [Home Assistant](https://www.home-assistant.io) app (formerly "add-on") that runs the
[Wazuh](https://wazuh.com) agent on Home Assistant OS and **enrolls it in your existing Wazuh
manager**, so the device is monitored next to your other endpoints.

> **Status: experimental.** The test suite runs the app against real Wazuh managers (enrollment,
> persistence, journal, file integrity, passwords) and CI runs it on amd64 and natively on arm64.
> It has not yet been verified on real Home Assistant OS hardware.

[![Add this repository to your Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbrianbaggs35%2Fha-wazuh-agent)

## Install

1. Add this repository to Home Assistant: use the button above, or open **Settings → Apps → App
   store → ⋮ → Repositories** and add `https://github.com/brianbaggs35/ha-wazuh-agent`.
2. Install **Wazuh Agent**, set **Wazuh manager address** in its Configuration tab, and start it.
3. The device appears under **Agents** in the Wazuh dashboard.

The full guide (ports, registration passwords, what is monitored, every option, troubleshooting)
is the app's [documentation](wazuh_agent/DOCS.md).

## What it does

- Enrolls with **just a manager address**; supports registration passwords, groups, certificate
  verification, failover managers and a fixed agent name.
- Reads the **host journal**: SSH logins, `sudo`, kernel warnings, Home Assistant Core (including
  failed web logins), the Supervisor and app errors.
- Watches the Home Assistant **configuration and certificates** for changes in real time, without
  ever sending the content of secrets.
- Reports **inventory** and runs **rootkit checks**; optional configuration assessment.
- Labels every event with the Home Assistant OS, Core and Supervisor versions.

## Designed to be safe to run

It asks Home Assistant for **no extra privileges**: no host network, no open ports, no added
capabilities, no full access, protection mode stays on, and it ships a custom AppArmor profile,
which gives the maximum Supervisor security rating (8/8; checked in CI). The trade-off, and what
that means for what can be seen, is explained in the
[Security](wazuh_agent/DOCS.md#security) section.

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
| Tests | Render tests (every Wazuh daemon checks the generated configuration) and end-to-end tests against the official `wazuh-manager` image: enrollment, persistence across restarts and updates, journal collection and filtering, file integrity, registration passwords, re-enrollment. |
| Architectures | `amd64` and `aarch64`, each built and tested on a native runner. |
| Scans | Trivy on the image (vulnerabilities, a gate on fixable HIGH and CRITICAL), configuration and secrets, plus an SBOM per release; SonarQube Cloud analysis of the code with its quality gate. |
| Releases | Published only after the exact images pass the tests and scans; the multi-arch image is signed with Sigstore and verified again from the registry. |

See [CONTRIBUTING.md](CONTRIBUTING.md) to run the tests yourself.

## Licence

The code in this repository is [MIT licensed](LICENSE). The image bundles the Wazuh agent, which
is licensed under the GNU GPL v2 by Wazuh, Inc., and the Home Assistant base image; their licences
apply to those parts.
