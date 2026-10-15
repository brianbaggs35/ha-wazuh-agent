# Security Policy

## Supported versions

Only the latest release of the app is supported. A vulnerability in this app or in what it
bundles (the Wazuh agent, the Debian base image) is fixed by releasing a new version, which
Home Assistant offers as a normal app update.

Every release's exact images pass the test suite and a Trivy gate (no fixable HIGH or CRITICAL
vulnerabilities) before they are published, and the published image is signed. A nightly scan
catches new vulnerabilities in already-released versions.

## Reporting a vulnerability

Please report it privately through **GitHub's "Report a vulnerability"** (Security tab of the
repository) rather than a public issue. Include the app version and what you observed. You will
get an acknowledgement and, if it is confirmed, a fixed release.

Vulnerabilities in Wazuh itself should be reported to Wazuh, Inc.; a fix reaches this app when a
new agent version is released and the app is updated.

## Design notes relevant to security

- The app asks Home Assistant for no extra privileges and ships an AppArmor profile; its
  security rating is checked in CI.
- Secrets (the registration password) are written to a file readable by root and the agent's
  account, never to the configuration file, a command line or the log.
- The content of `secrets.yaml`, `.storage` and `/ssl` is never sent to the manager by default.
- Remote command execution and active response are off by default.

See the *Security* section of [the documentation](wazuh_agent/DOCS.md#security).
