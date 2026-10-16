# Changelog

All notable changes to this app are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The app has its own version number (`MAJOR.MINOR.PATCH`), separate from Wazuh's.
Every entry says which Wazuh agent version the release contains. Updating the
agent means releasing a new version of this app, which Home Assistant then offers
as a normal app update.

Before updating the app, check that your Wazuh manager is not older than the agent
it will receive (see "Updating" in the documentation).

## [1.0.3] - 2026-10-16

Wazuh agent **4.14.9**.

### Changed

- **The app is now the Wazuh agent of the Home Assistant OS device itself**, as if the agent had
  been installed on it, instead of the agent of the container the app runs in. The agent's
  daemons run inside the host's own file system, so what the Wazuh dashboard shows, and what every
  Wazuh feature looks at, is the device: its real address (`192.168.x.x`, not the container's
  `172.30.x.x`), its host name, its operating system (Home Assistant OS), CPU, memory, processes,
  listening ports, user accounts and services; its files, logs and commands. Before, all of that
  described the app's Debian container.
- **Protection mode has to be turned off** for this (Info tab of the app, then restart it): Home
  Assistant shares the host's process namespace with an app only while Protection mode is off, and
  reaching the host takes it. With Protection mode on, the agent is not started and the status page
  and the log say what to do. Set the new option `monitor_host` to `false` to keep monitoring only
  the app's own container, the host journal and the Home Assistant folders, as before.
- **The security rating is lower, on purpose.** The app now asks Home Assistant for `host_pid`,
  `host_network`, `host_uts` and the `SYS_PTRACE` and `SYS_ADMIN` capabilities, which is what
  reaching the host takes (the documentation's Security section says what each one is for). It still
  asks for no full access, no Docker API, no published ports and no Supervisor role above the default.
  `tests/config/check_config.py` now guards that exact list instead of the maximum rating.
- The app supervises itself instead of using s6-overlay, which Home Assistant documents as unusable
  with the host's process namespace. The agent is still restarted if one of its daemons dies, and
  when Wazuh asks for a restart (new shared configuration from the manager): Wazuh's own
  `restart.sh` would restart through systemd, which on Home Assistant OS has no such service.
- The status page listens on the Supervisor's own network interface and on the port the Supervisor
  assigns (`ingress_port: 0`), because the app is on the host's network and a fixed port could be
  taken. It still answers only the Supervisor's ingress gateway.

### Added

- Native Wazuh defaults for the host: file integrity of `/etc`, `/usr/bin`, `/usr/sbin`, `/bin` and
  `/sbin`, with the same ignores a Wazuh package ships; the boot partition (`/mnt/boot`, which holds
  the SSH keys of the debug login), root's SSH keys and your own apps; the full inventory (processes,
  ports, users, groups, services); rootcheck that leaves out the containers' storage. New options
  `monitor_host`, `fim_host_defaults` and `inventory_host_details` switch these.
- The paths in the options are written the way the app sees its folders (`/homeassistant`, `/ssl`,
  `/config`, `/share`, ...); on the host they are turned into the host's own paths
  (`/mnt/data/supervisor/homeassistant`, ...), also in the file integrity patterns and in SCA policy
  paths. Alerts and inventory carry the host's paths.
- **The CPU shows in the Wazuh dashboard on ARM.** Wazuh reads a CPU's name only from the
  `model name` line of `/proc/cpuinfo`, which ARM kernels never print, so a Raspberry Pi showed no CPU.
  The app now works out the name (for example `Cortex-A76 (Raspberry Pi 5 Model B Rev 1.0)`) from what
  the kernel does print, and shows it to the agent in a private copy of `/proc/cpuinfo`. The host
  itself is not changed: the copy is visible only to the agent.
- The status page shows where the agent runs (the device, or only the app's container), and a
  **Host access is needed** state that says what to do when it cannot start.
- Tests: the end-to-end suite runs the app against a stand-in for the Home Assistant OS device and a
  real Wazuh manager, and checks that what the manager records (address, operating system, host
  name, CPU, processes, ports, accounts, file integrity paths, journal) is the device's and not the
  container's; that the real device is left untouched; and what happens when the host cannot be
  reached. Unit tests for the mount-table matching and the CPU naming run against realistic Home
  Assistant OS mount tables and Raspberry Pi `cpuinfo` files.

### Upgrading from 1.0.2

- The agent keeps its registration, but it now reports the device: its address, host name and
  operating system change in the Wazuh dashboard, and file integrity paths are the host's
  (`/mnt/data/supervisor/homeassistant/configuration.yaml` instead of
  `/homeassistant/configuration.yaml`). Rules or dashboards that match the old paths need adjusting.
- After the update the agent does not start until Protection mode is off (or `monitor_host` is
  `false`). Nothing else needs to be done.
- Options you saved before keep their values. `inventory_ports` and `inventory_processes` now apply
  only when `monitor_host` is `false`; for the host, `inventory_host_details` (on by default) decides.

### Known limitations

- Wazuh's vulnerability detection matches an agent's installed packages with vendor and open-source
  advisories. Home Assistant OS has no package manager and is not one of the operating systems Wazuh
  has vulnerability content for, so it reports nothing about the OS's own software, whatever the
  permissions. It does inventory the packages it finds in the standard places (dpkg, rpm, apk, Python
  and npm locations) when `inventory_packages` is on.
- Wazuh's Docker listener needs Python on the monitored machine, and Home Assistant OS has none.
- The automated tests use a stand-in for the device, not Home Assistant itself: the Supervisor, its
  Protection mode handling and AppArmor enforcement are not part of them.

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
