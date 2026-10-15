# Changelog

All notable changes to this app are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The app has its own version number (`MAJOR.MINOR.PATCH`), separate from Wazuh's.
Every entry says which Wazuh agent version the release contains. Updating the
agent means releasing a new version of this app, which Home Assistant then offers
as a normal app update.

Before updating the app, check that your Wazuh manager is not older than the agent
it will receive (see "Updating" in the documentation).

## [1.0.2] - 2026-10-15

Wazuh agent **4.14.9**.

### Changed

- The app is no longer marked experimental in the Home Assistant store.
- Documentation: a note on what the automated tests cover and what they do not (Home Assistant
  itself), and on the security rating, which the store shows as 7 until the app is installed
  and as 8 afterwards.
- Continuous integration: Trivy updated to 0.76.0, and an end-to-end check that failed now and
  then because of a closed pipe was made reliable. The app image is otherwise unchanged.

## [1.0.1] - 2026-10-15

Wazuh agent **4.14.9**.

### Changed

- First published release. Version 1.0.0 was tagged but never published: its release stopped
  at the changelog check, so no image exists for it. Everything listed under 1.0.0 below is part
  of this release, and nothing else changed.

## [1.0.0] - 2026-10-15

Never published (see 1.0.1).

Wazuh agent **4.14.9**.

### Added

- First release: the Wazuh agent as a Home Assistant app that enrolls into an
  existing Wazuh manager, so Home Assistant OS appears as a monitored endpoint.
- Enrollment with only a manager address; optional registration password, agent
  groups, certificate verification (CA, agent certificate and key), failover
  managers, UDP or TCP, and a fixed agent name (default: the Home Assistant host name).
- The agent keeps its identity (key, counters and databases) in the app's persistent
  storage, so restarts and app updates do not register a new agent.
- An unclean stop (power cut, forced stop) cannot block the next start: the process lock and
  PID files a killed run leaves in the persistent storage are cleared at start. Without this,
  Wazuh's start script can mistake the stale lock for a live one and refuse to start the agent.
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
- The permissions the agent needs were measured, not assumed (Wazuh documents ports, not
  capabilities): an end-to-end test runs it with only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`,
  `SETGID`, `SETUID` and `KILL`, with the reduced set a current Supervisor leaves a container,
  and with none, and checks that it enrolls and runs fully in the first two and not in the last.
- A read-only **Wazuh Agent** status page, shown as a sidebar panel through Home Assistant ingress:
  running, degraded or stopped; connected or not; the registration (agent ID and name, never the key);
  what is monitored; which services run; whether a newer Wazuh agent or app version exists; a
  connection test against the manager's ports; and the agent's log. It runs as an unprivileged
  account, answers only the Supervisor's ingress gateway, and needs no published port. The option
  `ui_update_check` turns the update lookup off.
- Continuous integration: lint, render and end-to-end tests against a real Wazuh manager,
  100% coverage of the Python, Go and web code, SonarQube Cloud and Trivy scans, and a release
  pipeline that publishes only after the tests and scans pass.

### Known limitations

- Not yet verified on real Home Assistant OS hardware (marked experimental).
- The agent sees the Home Assistant OS host through its journal and the folders Home
  Assistant maps into the app; host processes, host network connections and the host file
  system are not visible to an app running with default protection.
