# Wazuh Agent for Home Assistant

This app is the [Wazuh](https://wazuh.com) agent of your Home Assistant OS device. Installing it
does what installing the Wazuh agent directly on the device would do, which Home Assistant OS itself
does not let you do: the device is enrolled in **your existing Wazuh manager** and monitored like any
other endpoint, by its own name, address, operating system, processes, files and logs. Its alerts,
inventory and file integrity events appear in the Wazuh dashboard under **Agents**.

> **Protection mode must be off.** Reaching the device takes more access than a protected app has
> (see *Security*). After installing, open the app's **Info** tab, turn **Protection mode** off,
> then start it. The security rating Home Assistant shows for the app is low because of this access,
> and that is on purpose.

> **Testing.** The project's tests run the app against real Wazuh managers and a stand-in for the
> Home Assistant OS device (enrollment, restarts, journal collection, file integrity, what the
> manager records about the host, registration passwords). Home Assistant itself (the Supervisor, its
> handling of Protection mode, AppArmor enforcement, ingress) is not part of the automated tests.

Bundled agent: **Wazuh 4.14.9** (see the changelog for the version in each release).

## Before you start

| You need | Details |
| --- | --- |
| A Wazuh manager | Version 4.x, reachable from the Home Assistant device. |
| Port **1514/tcp** open to the manager | Where the agent sends events (UDP if you choose UDP). |
| Port **1515/tcp** open to the manager | Only needed to enroll the first time. |
| A compatible manager version | Wazuh requires the manager to be the same version as the agent **or newer**. In testing, the 4.14.9 agent connected to a 4.14.8 manager without trouble. An agent from a newer *minor* line (for example 4.15) will not connect to a 4.14 manager: upgrade the manager first. |
| **Protection mode off** for this app | On the app's **Info** tab. Home Assistant shares the device's process namespace with an app only while Protection mode is off, and the agent needs it to run on the device. (To monitor only the app's own container instead, see `monitor_host`.) |
| A supported device | `aarch64` (Raspberry Pi 4/5, Home Assistant Green and Yellow) or `amd64`. |

## Connect to Wazuh

1. **Install** the app.
2. Open its **Info** tab and turn **Protection mode** off.
3. Open its **Configuration** tab and set **Wazuh manager address** to the IP address or host name
   of your manager.
4. *If your manager requires a registration password* (its `authd.pass`), enter it in
   **Registration password**. If you never set one up, leave it empty.
5. *Optional:* choose an **Agent name** (the default is the Home Assistant host name) and
   **Agent groups** (they must already exist on the manager).
6. **Start** the app. In the **Log** tab you should see, within about half a minute:

   ```text
   The agent will run in the host's file system; its files are at /mnt/data/supervisor/addons/data/... on the host.
   wazuh-agentd: INFO: Valid key received
   wazuh-agentd: INFO: (4102): Connected to the server ([your-manager]:1514/tcp).
   ```

7. In the Wazuh dashboard open **Agents**: the device is listed as *Active* under the name
   you chose, with its real address (for example `192.168.1.20`), the operating system
   *Home Assistant OS* and its own CPU, memory, processes and ports.

That is the whole setup. Everything else in this document is optional tuning.

### If it does not connect

| What you see | What it means | What to do |
| --- | --- | --- |
| The status page says **Host access is needed**; the log says the agent was not started | Protection mode is on (or the app was not restarted after turning it off) | Info tab → Protection mode **off** → restart the app. To monitor only the app's own container, set `monitor_host` to `false`. |
| The log says the agent could not start in the host's file system | The device's system could not run the agent | Open an issue with the lines shown; meanwhile set `monitor_host` to `false`. |
| The app stops right away with a list of problems | A setting is invalid | The message names the option; fix it and start again. |
| `manager_address: required` | No manager address | Set **Wazuh manager address**. |
| The log shows connection errors to port 1515 | The enrollment service is unreachable | Check that 1515/tcp is open from this device to the manager (firewall, container networking). |
| The log shows connection errors to port 1514 | Enrollment worked but events cannot be sent | Check 1514/tcp (or UDP if you selected it). |
| Enrollment is refused with a password error | The manager requires a registration password | Set **Registration password** to the manager's `authd.pass`. |
| `ERROR: Duplicate agent name: <name>. Unable to add agent (from manager)` | Another agent already uses that name | Set a different **Agent name** (each Home Assistant installation needs its own), or delete the old agent on the manager and turn on **Enroll again on the next start** for one start. |
| The agent enrolled but shows *Disconnected* | The manager rejected or cannot reach the agent | Check the manager version (see above) and the manager's `/var/ossec/logs/ossec.log`. |
| The agent was deleted on the manager | Its saved key is no longer valid | Turn on **Enroll again on the next start**, start the app, then turn it **off** again. |

The container's health status (`docker ps` shows it) turns *healthy* only once the agent
is connected to the manager.

## The status page

Turn on **Show in sidebar** on the app's page and a **Wazuh Agent** entry appears in the Home
Assistant sidebar (or use **Open Web UI**). It refreshes every few seconds and has a dark and a
light theme.

The banner at the top says what state the agent is in:

| Banner | Meaning |
| --- | --- |
| **Running and connected** | The agent is connected to the manager and sending events. |
| **Connecting** | The agent is starting its connection to the manager. |
| **Cannot reach the manager** | The agent runs but is not connected: check the address, ports 1514 and 1515, and the manager's log. |
| **Running with a problem** | Connected, but one of the agent's services has stopped; the app restarts the agent if it does not come back. |
| **Agent stopped** | The agent is not running. The app restarts it; if this persists, read the log. |
| **Host access is needed** | The agent was asked to monitor the device and cannot: most often Protection mode is on. The banner says what to do; nothing was started. |
| **Starting** / **Status is not updating** | The app has only just started, or its supervisor has stopped reporting. |

Below it, cards show:

| Card | What it tells you |
| --- | --- |
| **Registration** | The name and agent ID the manager knows this device by, its groups, config profile and how it enrolled. The agent's key is never shown. |
| **Connection** | Manager address, last keep-alive and reply, messages sent and waiting, and a **Test the connection** button that tries the manager's ports from the app. |
| **Agent services** | Each Wazuh service (connection, log collection, file integrity, inventory, ...) and whether it runs. |
| **What is monitored** | Which sources are switched on: journal, file integrity, inventory, rootkit checks, configuration assessment, and whether active response and remote commands are allowed. |
| **Updates** | Whether Wazuh has published a newer agent than the one in this app, and whether a newer version of the app exists. Updating the agent means updating the app (see *Updating*). |
| **This device** | Where the agent runs (the device, or only the app's container), the device's name and the Home Assistant versions the labels describe. |
| **Agent log** | The tail of the agent's log, with a copy button. |

The page is read-only: it cannot start, stop or change anything. It is served by an
unprivileged account and answers only the Supervisor's ingress gateway, on the Supervisor's own
network interface, so it is not reachable from your network and the app opens no port. Its update
lookup is the only thing that goes beyond the manager: one HTTPS request to `packages.wazuh.com`
(Wazuh's package index) at most every few hours. Set `ui_update_check` to off to stop it; the page
then says it is disabled.

## What is monitored

The agent runs inside the device's own file system, so every Wazuh feature looks at the device:

| Source | What you get | On by default |
| --- | --- | --- |
| **Host journal** | SSH logins (`sshd`, `dropbear`), `sudo`/`su`/`login`, kernel warnings, **Home Assistant Core** logs (including failed web login attempts), **Supervisor** logs, and errors from any service. Optionally every app's logs, or the entire journal. | Yes (not apps/all) |
| **File integrity** | Added, changed and deleted files in the Home Assistant configuration and certificates, **and** what a Wazuh agent watches on any Linux machine (`/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`) plus the boot partition (`/mnt/boot`, where the SSH keys of the debug login live), root's SSH keys (`/root/.ssh`) and your own apps (`/mnt/data/supervisor/addons/local`). Real time where it matters. | Yes |
| **System inventory** | The device's hardware (CPU name, cores, memory), its operating system and version, network interfaces and its real address, **processes**, **listening ports** (with the process that opened them), **user accounts and groups**, **services**, and the **Python packages of Home Assistant Core**. | Yes |
| **Rootkit checks** | Known rootkit files, trojaned binaries, `/dev`, network interfaces and system file permissions, on the device. | Yes (process and port checks: no) |
| **Configuration assessment (SCA)** | Policy checks run against the device, with policies you supply (Wazuh's built-in ones are written for Debian, Ubuntu and similar systems). | No |
| **Custom logs and commands** | Any file or command output you add. Commands run on the device. | None |
| **Active response** | Scripts the manager triggers run on the device. | No |

Wazuh's built-in rules apply on the manager: for example, a failed SSH login on the device
raises **rule 5710** with its MITRE ATT&CK mapping, and a change to `configuration.yaml`
raises a file integrity alert.

### Paths: the app's folders and the device's

Home Assistant gives the app its folders under short names (`/homeassistant`, `/ssl`, `/config`,
...); on the device they are elsewhere, and the agent works with the device's paths. You keep writing
the short names in the options: the app turns them into the device's paths when it starts (the
agent's alerts and inventory then carry the device's paths).

| In an option, write | On the device it is |
| --- | --- |
| `/homeassistant` | `/mnt/data/supervisor/homeassistant` |
| `/ssl` | `/mnt/data/supervisor/ssl` |
| `/config` (this app's configuration folder) | `/mnt/data/supervisor/addon_configs/<this app's folder>` |
| `/share`, `/media`, `/backup` | `/mnt/data/supervisor/share`, `.../media`, `.../backup` |
| `/data` (this app's data) | `/mnt/data/supervisor/addons/data/<this app's folder>` |
| Anything else (`/etc/ssh`, `/var/log/messages`, `/mnt/boot`) | The device's own path |

The app finds the real locations itself, from the mount tables of the device, and does not assume
these. Where an option takes a regular expression anchored at a folder (`^/ssl/`), the folder is
translated too. In `ossec_extra.conf`, `ossec.conf` and in the commands of `log_commands` nothing is
translated: write the device's paths there.

### Limits

- **Vulnerability detection.** Wazuh's vulnerability detection matches the packages an agent
  reports with vendor and open-source advisories. Home Assistant OS has no package manager and is not
  one of the operating systems Wazuh has vulnerability content for (Wazuh's compatibility matrix
  lists, among others, Debian, Ubuntu, Red Hat, SUSE and Amazon Linux, plus Python and npm packages),
  so it reports nothing about the software of the operating system itself, whatever the permissions of
  the agent. What it can match on a Home Assistant device is Python: Home Assistant Core is a Python
  application, and the agent reports the packages Core runs on (see `inventory_core_packages`), which
  Wazuh has advisories for. Those findings appear on a manager that has vulnerability detection set
  up. The Python packages of apps (add-ons) are not included, and the packages of other software in
  the standard places (dpkg, rpm, apk, npm) are in the inventory only when **Inventory - packages**
  is on.
- **Container security.** Wazuh's Docker listener needs Python on the monitored machine, and Home
  Assistant OS has none. Docker's own events are in the journal.
- **The device's own agent management.** The agent is part of this app's image, so it is updated
  by updating the app (see *Updating*), not by the manager's remote upgrade.
- **Security configuration assessment.** Wazuh's built-in policies do not fit Home Assistant OS.
  Write your own; they run against the device.

## Labels

With **Add Home Assistant labels** on (the default), every event carries these labels, so
you can filter on them in the dashboard (for example `agent.labels.ha_core_version`):

`ha_os`, `ha_os_version`, `ha_core_version`, `ha_supervisor_version`, `ha_machine`,
`ha_arch`, `ha_channel`, `ha_app_version`. Add your own under **Custom labels**.

## Configuration reference

Every option can be set in the app's **Configuration** tab (list options in YAML mode).
Defaults are shown in the tab itself; the grouping below follows it.

### Where the agent runs

| Option | Purpose |
| --- | --- |
| `monitor_host` | On (the default): the agent runs against the Home Assistant OS device, as described above. Needs Protection mode off. Off: the agent monitors only this app's own container (its Debian system, the host journal and the Home Assistant folders mapped into it); Protection mode can stay on. The privileges the app declares do not change with this option. |

### Connection

| Option | Purpose |
| --- | --- |
| `manager_address` | **Required.** Manager IP address or host name. |
| `manager_port`, `manager_protocol` | Event port (1514) and `tcp` (default) or `udp`. |
| `manager_failover_addresses` | More managers, tried in order (a Wazuh cluster). |
| `server_max_retries`, `server_retry_interval` | Retries per manager and seconds between them. |
| `notify_time`, `time_reconnect` | Keep-alive interval and reconnect delay, in seconds. |
| `crypto_method` | `aes` (default) or `blowfish`. Keep AES. |
| `auto_restart` | Restart when the manager pushes new centralized configuration. |
| `config_profile` | Profile name(s) the manager can target in `agent.conf`. Default `homeassistant`. |
| `buffer_enabled`, `buffer_queue_size`, `buffer_events_per_second` | The agent's event buffer. |

### Enrollment and identity

| Option | Purpose |
| --- | --- |
| `enrollment_enabled`, `enrollment_address`, `enrollment_port` | Automatic enrollment and where the enrollment service is (default 1515, same host as the manager). |
| `enrollment_password` | The manager's registration password, if it requires one. |
| `enrollment_ca_path` | CA certificate to verify the manager's identity, for example `/config/ca.pem`. |
| `enrollment_certificate_path`, `enrollment_key_path` | Agent certificate and key, to prove the agent's identity to the manager. Set both or neither. |
| `enrollment_delay`, `enrollment_use_source_ip` | Wait after enrolling; register with the source IP (leave off behind NAT). |
| `force_reenroll` | Discard the saved key and enroll again on this start. **Turn it off afterwards.** |
| `agent_name`, `agent_groups` | Name in Wazuh and groups to join. |
| `auto_labels`, `agent_labels` | Home Assistant labels and your own key/value labels. |

### Log collection

| Option | Purpose |
| --- | --- |
| `journal_enabled` | Read the host journal at all. |
| `journal_auth`, `journal_kernel`, `journal_homeassistant`, `journal_supervisor`, `journal_errors` | Which parts of the journal to send (default on). |
| `journal_apps`, `journal_all` | Every app's logs, or the whole journal (default off, can be very noisy). |
| `journal_filters` | Extra filters on one journal field each (`field`, `pattern`, `ignore_if_missing`). |
| `ha_core_log_enabled` | Also read `home-assistant.log` in the Home Assistant configuration folder (already in the journal). |
| `log_files` | Extra log files: `path`, `format`, `only_future_events`, `ignore`, `restrict`, `exclude`, `age`. |
| `log_commands` | Command output as events: `command`, `format`, `frequency`, `alias`. The command runs on the device. |

### File integrity monitoring

| Option | Purpose |
| --- | --- |
| `fim_enabled`, `fim_frequency`, `fim_scan_on_start` | Turn it on, full-scan interval, scan at start. |
| `fim_host_defaults` | Also watch the device's system files: `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, the boot partition `/mnt/boot`, root's SSH keys `/root/.ssh` and your own apps `/mnt/data/supervisor/addons/local`, with the ignores a Wazuh package ships. Only when monitoring the device. Your own directories are added to these. |
| `fim_directories` | Paths to watch: `path`, `realtime`, `report_changes`, `check_all`, `restrict`, `tags`, `recursion_level`. |
| `fim_ignore`, `fim_ignore_sregex` | Paths and patterns to leave out (defaults skip logs, databases, caches). |
| `fim_nodiff`, `fim_nodiff_sregex` | Paths whose **content is never sent** (default: `secrets.yaml`, `.storage`, `/ssl`; with `fim_host_defaults` also the password files). |
| `fim_max_eps`, `fim_process_priority`, `fim_file_limit` | Throttling, scanner priority, file cap. |
| `fim_sync_enabled`, `fim_sync_interval`, `fim_sync_max_eps` | Inventory synchronization with the manager. |

`fim_ignore_sregex` uses Wazuh's *simple* regular expressions: `^` and `$` anchor, `|` means
"or", and everything else, including `.`, matches literally.

### Rootkit checks, SCA and inventory

`rootcheck_*` toggle each check and its frequency. `sca_enabled`, `sca_interval`,
`sca_scan_on_start`, `sca_skip_nfs` and `sca_policies` control security configuration
assessment (list your own policy files in `sca_policies`). `inventory_*` toggle the
inventory sections and the interval.

| Option | Purpose |
| --- | --- |
| `inventory_host_details` | Report the device's processes, listening ports, user accounts, groups and services (on by default). Only when monitoring the device. |
| `inventory_core_packages` | Include the Python packages Home Assistant Core runs on in the inventory (on by default). They are what Wazuh's vulnerability detection can match on a Home Assistant device. Only when monitoring the device. |
| `inventory_ports`, `inventory_processes` | The same for the app's own container; only used when `monitor_host` is off. |
| `inventory_packages` | Installed packages of the standard package managers (dpkg, rpm, apk) and of Python and npm in their usual places. Home Assistant OS has none of its own (see *Limits*); for the app's own container it lists the Debian packages of its image. |

The rootkit checks for hidden processes and hidden ports are off by default: on a device that runs
many containers they can raise false alarms. They are meaningful on the device, so turn them on if
you want them.

### Response and advanced

| Option | Purpose |
| --- | --- |
| `active_response_enabled` | Let the manager run response scripts on the agent. They run on the device. Off by default. |
| `allow_remote_commands` | Let the manager push command execution settings. **Off by default**; see *Security*. |
| `debug_level` | 0 normal, 1 debug, 2 verbose. |
| `log_max_size_mb` | The agent's own log files are trimmed above this size. |
| `use_custom_ossec_conf` | Use `/config/ossec.conf` verbatim. |

### Characters that are not allowed

The Wazuh configuration format cannot represent a few characters inside values, so the
app refuses them with a clear message instead of writing a broken file: **`<`**, line
breaks, and a single backslash at the very end of a value. Everything else, including `&`,
quotes and backslashes elsewhere, is written exactly as you typed it (type a regular
expression once; do not double its backslashes). If you need `<`, use `ossec_extra.conf`.

## The app's configuration folder

The app mounts its own configuration folder, read-only, at `/config`. Open it with the
File editor or Samba app (look for a folder ending in `_wazuh_agent` under `addon_configs`;
newer Home Assistant versions call the share `app_configs`). Files you can put there:

| File | Effect |
| --- | --- |
| `ossec_extra.conf` | Extra `<ossec_config>` blocks appended to the generated configuration. Use it for anything without an option. Write the device's own paths in it. |
| `local_internal_options_extra.conf` | Extra lines appended to Wazuh's `local_internal_options.conf`. |
| `ossec.conf` | A complete configuration, used instead of the generated one when `use_custom_ossec_conf` is on. |
| Certificates, policies | Anything you reference by path in the options: CA and agent certificates (`/config/ca.pem`), SCA policies (`/config/sca/home-assistant.yml`). |

Example `ossec_extra.conf`:

```xml
<ossec_config>
  <labels>
    <label key="room">basement</label>
  </labels>
</ossec_config>
```

## Security

### Why the security rating is low

Home Assistant rates every app from 1 to 8 by the access it asks for. This app is rated **3**, and
that is deliberate: it is the Wazuh agent of the device, not of a container, and a container cannot
see the device it runs on. An agent installed on the device runs as root and sees everything; this
app asks Home Assistant for what it takes to do the same, and the rating reports that.

| Setting | What it gives the app | What the agent uses it for |
| --- | --- | --- |
| `host_pid` | The device's process namespace (Home Assistant applies it only while **Protection mode is off**) | Seeing the device's processes, and reaching the device's file system to run the agent in it |
| `host_network` | The device's network | The device's real address, its interfaces and its listening ports, instead of the container's |
| `host_uts` | The device's host name | Reporting the device's name |
| `SYS_PTRACE` | Reading the namespaces of processes that hold more privileges than the container (the kernel refuses otherwise, whatever the user) | Finding and joining the device's file system |
| `SYS_ADMIN` | Joining the device's mount namespace, and mounting inside a private copy of it | Running the agent in the device's file system, with the private overlay below |

**Treat the app as having root on the device.** Wazuh agents do on any machine they monitor, and
this one is no different. What it does not ask for: full access to the hardware, the Docker API,
published ports, or a Supervisor role above the default (it makes info calls only, for the agent name
and the labels). A custom **AppArmor profile** still limits what the app's processes may signal and
trace, and denies the kernel's memory image and the sysrq trigger. The image is built from a
**digest-pinned Debian base**, and the agent is installed from Wazuh's official apt repository: the
build fails if the repository's signing key ever differs from the pinned fingerprint.

The security rating Home Assistant shows is computed from the app's declared access, so
`monitor_host: false` does not raise it. Home Assistant applies `host_network`, `host_uts` and the
capabilities whatever Protection mode says; only the device's process namespace depends on it. With
Protection mode on and `monitor_host` off, the agent sees the app's own container.

### How the agent runs on the device

Home Assistant OS is a read-only image with no package manager, so the agent cannot be installed in
it. Instead the app starts the agent's daemons from its own data folder (which the device sees
under `/mnt/data/supervisor/addons/data/...`), inside a **private copy of the device's mount
namespace**. In it, every path is the device's own, exactly as for an agent installed there. The
private copy has two things laid over the device's files, and only the agent sees them:

- the device's account files with one more line each, for the `wazuh` account every Wazuh package
  creates (the agent drops to it), and
- on ARM, a `/proc/cpuinfo` with the CPU's name added (Wazuh reads the name only from there, and ARM
  kernels do not print it), and
- an empty `/home` with one folder in it, which Wazuh reads as the place a user keeps Python
  packages and which leads to the Python packages of Home Assistant Core. Home Assistant OS has no
  Python of its own; Core is a container, and its file system is reachable through its processes
  (`/proc/<pid>/root`), read-only as the agent uses it. The app keeps the link current when Core
  restarts.

Nothing about the device is changed: the app's own data folder is the only thing it writes on it, the
overlay mounts cannot propagate back (the tests check the real device's account files, `cpuinfo`, `/home`
and mount table afterwards), and when the app stops, the agent's processes are stopped with it.

The agent's processes are supervised by the app, not by the device: Wazuh's own restart script
restarts through systemd when it finds one, which on Home Assistant OS would be a restart of a service
that does not exist, so the app installs a restart script that asks the app to restart the agent.

### Permissions, and how they were checked

Wazuh's documentation lists what an agent needs from the **network** (outbound 1514/tcp, or UDP if
chosen, to send events; outbound 1515/tcp to enroll) and nothing about Linux capabilities, so the
test suite measures them: against a real manager, in a plain container, the agent enrolls, connects
and runs all five daemons with only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID` and `KILL`,
with the reduced set a current Supervisor leaves a container, and not at all with none. Running on the
device adds `SYS_PTRACE` and `SYS_ADMIN` (and `SYS_CHROOT`, which every container has by default).

What the agent can read is decided by the device it runs on; the folders Home Assistant maps into the
app (configuration and certificates, read-only) and the host journal are also there for the
container-only mode.

### What your Wazuh manager can do

An agent trusts its manager. The manager can push centralized configuration to this agent, including
extra files to monitor, and **with the agent on the device that means files of the whole device**.
The defaults limit the damage of a compromised or mistaken manager: the content of `secrets.yaml`,
`.storage`, `/ssl` and the password files is never sent (`fim_nodiff*`), `allow_remote_commands` is
off (so the manager cannot make the agent run commands), and active response is off. Turn the last two
on only if you need them, and know that they then act on the device. Keep your manager patched and its
enrollment protected with a registration password.

### Secrets

The registration password is written to a file readable only by root and the agent's
account and is never written to the configuration file, the log or a command line. The
agent's key is stored in the app's persistent storage and is included in Home Assistant
backups: restore a backup only onto the device it came from, or two devices would claim
the same Wazuh identity.

## Updating

Updating the Wazuh agent means a **new version of this app**: the agent is part of the
image and is never replaced while the app runs. Home Assistant shows the update in the
normal way (and you can enable automatic updates). Each release's changelog says which
Wazuh agent version it contains. A scheduled job in the project's repository checks
weekly and opens a change when Wazuh has published a new stable agent; it is tested against
a real manager and scanned before it is released.

**Update your Wazuh manager first** when an update moves to a newer Wazuh minor version
(for example 4.14 to 4.15), because the manager must not be older than the agent.

The agent keeps its identity and databases across updates.

## Backups

The app uses *cold* backups (it is stopped while the backup runs), so the agent's
databases are consistent. A restored backup comes back with the agent's key; see *Secrets*.

## Troubleshooting

- **More detail:** set `debug_level` to 1 or 2 and restart; the agent's own log is shown in
  the app's **Log** tab.
- **The app starts but nothing is monitored:** the status page says **Host access is needed**. Turn
  Protection mode off on the Info tab and restart the app.
- **No journal events:** the app log says `Host journal found; using its machine ID...` when
  it runs in the container, or the journal is the device's own when it runs on the device. If there
  is nothing, check that the app was updated to a version declaring `journald`.
- **Alerts carry other paths than before 1.0.3:** file integrity paths are the device's own now (for
  example `/mnt/data/supervisor/homeassistant/configuration.yaml`); adjust rules and dashboards that
  match the old ones.
- **File integrity "inotify" messages:** real-time watching is limited by the host's
  `fs.inotify.max_user_watches`. Watch fewer directories in real time, or set
  `realtime: false` for large ones.
- **Several Home Assistant installations:** give each its own `agent_name`.
- **Check the generated configuration:** it is rewritten at every start; compare with your
  options if something is not applied.
