# Changelog

All notable changes to this app are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The app has its own version number (`MAJOR.MINOR.PATCH`), separate from Wazuh's.
Every entry says which Wazuh agent version the release contains. Updating the
agent means releasing a new version of this app, which Home Assistant then offers
as a normal app update.

Before updating the app, check that your Wazuh manager is not older than the agent
it will receive (see "Updating" in the documentation).

## [1.0.0] - unreleased

Wazuh agent **4.14.9**.

### Added

- First release: the Wazuh agent as a Home Assistant app that enrolls into an
  existing Wazuh manager, so Home Assistant OS appears as a monitored endpoint.
- Enrollment with only a manager address; optional registration password, agent
  groups, certificate verification (CA, agent certificate and key), failover
  managers, UDP or TCP, and a fixed agent name (default: the Home Assistant host name).
- The agent keeps its identity (key, counters and databases) in the app's persistent
  storage, so restarts and app updates do not register a new agent.
- Host journal collection with sensible presets (logins, kernel warnings, Home Assistant
  Core, Supervisor, errors, optionally all apps) plus custom journal filters. The app
  adopts the host journal's machine ID, without which Wazuh silently ignores it.
- File integrity monitoring of the Home Assistant configuration and certificates, in real
  time, with defaults that skip the recorder database, logs and caches and never send
  the content of `secrets.yaml`.
- System inventory, rootkit checks, optional security configuration assessment with your
  own policies, custom log files and command output.
- Home Assistant labels on every event (OS, Core, Supervisor and app versions, machine
  and architecture) for filtering in the Wazuh dashboard.
- Escape hatches for anything without an option: `ossec_extra.conf`,
  `local_internal_options_extra.conf` and a full `ossec.conf` override in the app's
  configuration folder.
- Configuration is validated before the agent starts: problems are reported together,
  by option name, and every Wazuh daemon checks the generated configuration itself.
- Runs with no extra privileges (no host network, ports, capabilities, full access or
  Docker API), a custom AppArmor profile and a digest-pinned Debian base image, for the
  maximum Home Assistant security rating.
- Container health reports whether the agent is connected to the manager.
- Continuous integration: lint, render and end-to-end tests against a real Wazuh manager,
  Trivy scans, and a release pipeline that publishes only after the tests and scans pass.

### Known limitations

- Not yet verified on real Home Assistant OS hardware (marked experimental).
- The agent sees the Home Assistant OS host through its journal and the folders Home
  Assistant maps into the app; host processes, host network connections and the host file
  system are not visible to an app running with default protection.
