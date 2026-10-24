# Changelog

All notable changes to this app are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The app has its own version number (`MAJOR.MINOR.PATCH`), separate from Wazuh's.
Every entry says which Wazuh agent version the release contains. Updating the
agent means releasing a new version of this app, which Home Assistant then offers
as a normal app update.

Before updating the app, check that your Wazuh manager is not older than the agent
it will receive (see "Updating" in the documentation).

## [1.0.5] = 2026=10-23

Wazuh agent **4.14.9**.

### Updates

- Updated vite to 8.3.5
- Updated vuetify to 4.3.0
- Updated @vitest/coverage-v8 to 5.0.5
- Updated vitest to 5.0.5
- Updated eslint to 10.13.0
- Updated typescript-eslint to 8.72.0
- Updated home-assistant/base-debian from a7f262f to e222afd

## [1.0.4] - 2026-10-17

Wazuh agent **4.14.9**.

### Fixed

- **Home Assistant's Python packages were missing from the inventory, so vulnerability detection had nothing to
  match.** Version 1.0.3 found Home Assistant Core by its command line, `python3 -m homeassistant`. Since Home
  Assistant 2026.9 its container starts as `python3 -P -m homeassistant`, which 1.0.3 did not recognise, so it
  never linked Core's packages to the agent: of the roughly 1,600 Python packages Core runs on, none reached the
  Wazuh dashboard's *Software* inventory or its vulnerability detection. The app now reads the command line the
  way Python does (options first, the first `-m` names the module), so this form, the older one and the
  variations Python allows are all recognised, and it says in its log whether it found Core
  (`Home Assistant Core (process 1234): its Python packages are in the inventory.`) or did not. The 1.0.3
  end-to-end test had the same blind spot: its stand-in for Core was a process named as 1.0.3 expected, not started
  the way Core's container starts it. Checked now against the real thing: with the real Home Assistant Core
  2026.10.2 container on the real Home Assistant OS 18.3 file system, the manager's inventory goes from 0 packages
  (1.0.3) to 1,627 (this release), which is the number of Python packages in that image.
- Documentation that was not true: the boot partition (`/mnt/boot`) does not hold the debug login's SSH keys, it
  is where a `CONFIG` folder with them is put to be imported (Home Assistant OS then copies them to
  `/root/.ssh/authorized_keys` and removes the folder), and Home Assistant OS does have a Python of its own on
  some builds (see *Known limitations*).

### Added

- **Configuration assessment of the device.** The Wazuh dashboard's *Configuration Assessment* was empty because
  the assessment was off by default and the only policy in the agent, Wazuh's CIS benchmark for Debian 13, does
  not apply to Home Assistant OS. The app now ships its own policy, `home_assistant_os`, with eight checks of
  things Home Assistant OS sets up or that its owner can change: debug SSH access (port 22222) is off, no SSH
  key waits on the boot partition, only root has user ID 0, the Docker socket is not open to everyone, the data
  partition is less than 90% full, the kernel's protections for links and files in shared directories are on,
  no file in `/etc` can be changed by every account, and the Wazuh manager cannot run commands on the device
  through the agent. Every check carries what it looked at, why it matters and what to do. The new option
  `sca_host_policy` (on by default, only when monitoring the device) switches it. It is independent of
  `sca_enabled`, which keeps running policies of your own (`sca_policies`), so devices where 1.0.2 or 1.0.3
  saved `sca_enabled: false` are assessed after the update without touching the configuration.
- **The Python packages of the Home Assistant Supervisor** are in the inventory too (option
  `inventory_core_packages`, which now covers Core and the Supervisor): the Supervisor is a Python application
  with dependencies of its own. A program that starts after the agent is found without restarting the agent.
- Documentation: how to collect the audit log that Home Assistant OS writes (`log_files` with the `audit` format),
  checked on the real Home Assistant OS 18.3 file system with a sample AppArmor denial, which the manager reports.
- Tests: the end-to-end suite starts its stand-ins for Core and the Supervisor with the real command lines and
  the Python packages where the official Python image keeps them, checks that a program that starts later is
  found, that its packages follow it when it restarts, and that the manager records every check of the new policy
  with the right result (and sees a change on the device at the next assessment). Unit tests recognise 22 command
  lines, among them both forms of Core's container's (as its run script has them at the tags from 2025.6.0 to
  2026.10.2) and the Supervisor's; the configuration guard checks the policy's structure, check IDs and rule syntax.

### Changed

- `sca_policies` (your own policy files) run only while `sca_enabled` is on. Before, they were listed in the
  generated configuration whatever the switch said; with the assessment off they never ran, and now that the
  app's own policy can switch the assessment on by itself, listing them would have run them.
- The agent's log says `Skipping policy ... cis_debian13.yml` at each assessment: Wazuh's own Debian policy is
  loaded and does not apply to Home Assistant OS. That is expected.

### Upgrading from 1.0.3

- Nothing to configure. After the update and a restart the app's log shows which of Core and the Supervisor it
  found, the Python packages appear in the inventory after the next inventory scan, and the first
  configuration assessment reaches the manager a few minutes after the start.
- A check that *fails* reports a state: with debug SSH access enabled on purpose, the first one will fail.
  Set `sca_host_policy` to `false` to stop the assessment.
- Option values you saved keep their values.

### Known limitations

- Wazuh's vulnerability detection reports on packages: Home Assistant OS has none of its own and is not an
  operating system Wazuh has vulnerability content for, so it reports nothing about the OS's own software. What
  it can match is Python (Core's and the Supervisor's packages; not those of apps). Whether it matches them on an
  operating system it does not know is read from Wazuh's source, not observed: the vulnerability detection needs
  Wazuh's indexer and feed, which the tests do not run. It only lists packages that are vulnerable, so an empty
  vulnerability panel next to a full inventory is normal.
- Wazuh's Docker listener needs the `docker` Python module, which Home Assistant OS does not have (some builds carry
  a small Python 3.12 without it and without SSL, the generic x86-64 build none).
- The automated tests use a stand-in for the device and for Home Assistant's containers, not Home Assistant
  itself: the Supervisor, its Protection mode handling, the way it installs the AppArmor profile and ingress are not
  part of them. For this release the app was also checked by hand, outside the automated tests, against the real
  Home Assistant OS 18.3 file system (x86-64) and the real Core and Supervisor images, not on a device.

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
- **Home Assistant Core's Python packages are in the inventory** (new option
  `inventory_core_packages`, on by default). Home Assistant OS has no package manager for Wazuh's
  vulnerability detection to match, but Core is a Python application, and Python packages are
  something Wazuh has advisories for. The agent finds Core through its processes and shows the
  packages to Wazuh at the place Wazuh looks for a user's Python packages; the link is kept
  current when Core restarts.
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
  permissions. What it can match is Python: the packages Home Assistant Core runs on are inventoried.
  The Python packages of apps are not.
- Wazuh's Docker listener needs Python on the monitored machine, and Home Assistant OS has none.
- The automated tests use a stand-in for the device, not Home Assistant itself: the Supervisor, its
  Protection mode handling, the way it installs the AppArmor profile and ingress are not part of them.
  The profile itself is loaded into the kernel of the test machines, and the agent runs under it.

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
