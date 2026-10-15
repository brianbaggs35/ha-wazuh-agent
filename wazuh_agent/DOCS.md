# Wazuh Agent for Home Assistant

This app runs the [Wazuh](https://wazuh.com) agent on Home Assistant OS and enrolls it in
**your existing Wazuh manager**, so the Home Assistant device is monitored alongside your
other endpoints: its alerts, inventory and file integrity events appear in the Wazuh
dashboard under **Agents**.

> **Testing.** The project's tests run the app against real Wazuh managers (enrollment,
> restarts, journal collection, file integrity, registration passwords). Home Assistant
> itself (the Supervisor, AppArmor enforcement, ingress) is not part of the automated tests.

Bundled agent: **Wazuh 4.14.9** (see the changelog for the version in each release).

## Before you start

| You need | Details |
| --- | --- |
| A Wazuh manager | Version 4.x, reachable from the Home Assistant device. |
| Port **1514/tcp** open to the manager | Where the agent sends events (UDP if you choose UDP). |
| Port **1515/tcp** open to the manager | Only needed to enroll the first time. |
| A compatible manager version | Wazuh requires the manager to be the same version as the agent **or newer**. In testing, the 4.14.9 agent connected to a 4.14.8 manager without trouble. An agent from a newer *minor* line (for example 4.15) will not connect to a 4.14 manager: upgrade the manager first. |
| A supported device | `aarch64` (Raspberry Pi 4/5, Home Assistant Green and Yellow) or `amd64`. |

## Connect to Wazuh

1. **Install** the app and open its **Configuration** tab.
2. Set **Wazuh manager address** to the IP address or host name of your manager.
3. *If your manager requires a registration password* (its `authd.pass`), enter it in
   **Registration password**. If you never set one up, leave it empty.
4. *Optional:* choose an **Agent name** (the default is the Home Assistant host name) and
   **Agent groups** (they must already exist on the manager).
5. **Start** the app. In the **Log** tab you should see, within about half a minute:

   ```text
   wazuh-agentd: INFO: Valid key received
   wazuh-agentd: INFO: (4102): Connected to the server ([your-manager]:1514/tcp).
   ```

6. In the Wazuh dashboard open **Agents**: the device is listed as *Active* under the name
   you chose.

That is the whole setup. Everything else in this document is optional tuning.

### If it does not connect

| What you see | What it means | What to do |
| --- | --- | --- |
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
| **Starting** / **Status is not updating** | The app has only just started, or its supervisor has stopped reporting. |

Below it, cards show:

| Card | What it tells you |
| --- | --- |
| **Registration** | The name and agent ID the manager knows this device by, its groups, config profile and how it enrolled. The agent's key is never shown. |
| **Connection** | Manager address, last keep-alive and reply, messages sent and waiting, and a **Test the connection** button that tries the manager's ports from the app. |
| **Agent services** | Each Wazuh service (connection, log collection, file integrity, inventory, ...) and whether it runs. |
| **What is monitored** | Which sources are switched on: journal, file integrity, inventory, rootkit checks, configuration assessment, and whether active response and remote commands are allowed. |
| **Updates** | Whether Wazuh has published a newer agent than the one in this app, and whether a newer version of the app exists. Updating the agent means updating the app (see *Updating*). |
| **This device** | The Home Assistant versions and machine the labels describe. |
| **Agent log** | The tail of the agent's log, with a copy button. |

The page is read-only: it cannot start, stop or change anything. It is served by an
unprivileged account and answers only the Supervisor's ingress gateway, so it is not reachable
from the network and the app opens no port. Its update lookup is the only thing that goes
beyond the manager: one HTTPS request to `packages.wazuh.com` (Wazuh's package index) at most
every few hours. Set `ui_update_check` to off to stop it; the page then says it is disabled.

## What is monitored

| Source | What you get | On by default |
| --- | --- | --- |
| **Host journal** | SSH logins (`sshd`, `dropbear`), `sudo`/`su`/`login`, kernel warnings, **Home Assistant Core** logs (including failed web login attempts), **Supervisor** logs, and errors from any service. Optionally every app's logs, or the entire journal. | Yes (not apps/all) |
| **File integrity** | Added, changed and deleted files in the Home Assistant configuration (`/homeassistant`) and certificates (`/ssl`), detected in real time. | Yes |
| **System inventory** | Hardware (the device's CPU and memory), operating system, and network details. | Yes |
| **Rootkit checks** | Known rootkit files and anomalies. | Yes (reduced) |
| **Configuration assessment (SCA)** | Policy checks. Runs your own policies. | No |
| **Custom logs and commands** | Any file or command output you add. | None |

Wazuh's built-in rules apply on the manager: for example, a failed SSH login on the device
raises **rule 5710** with its MITRE ATT&CK mapping, and a change to `configuration.yaml`
raises a file integrity alert.

### What it cannot see

Home Assistant runs apps in protected containers, and this app stays inside that
protection on purpose (see *Security*). That has consequences for what is monitored:

- The agent runs **inside its own container**. Inventory of *processes*, *network
  connections*, *open ports* and *packages* describes that container, not the Home
  Assistant OS host, which is why those are off by default.
- The host's own files (the OS image, `/etc`, `/root`, `/mnt/data`) are not visible. The
  folders Home Assistant maps into the app (configuration and certificates) are.
- In Wazuh the device's operating system shows as the app's Debian base. Use the Home
  Assistant labels (below) to see the real Home Assistant OS version.
- Rootkit checks and the built-in CIS policy evaluate the container, so
  hidden-process and hidden-port checks are off and SCA is off by default.

The host journal, however, includes the logs of Home Assistant Core, the Supervisor, the
host's SSH service and the kernel, which is where the security-relevant events on a Home
Assistant device are.

## Labels

With **Add Home Assistant labels** on (the default), every event carries these labels, so
you can filter on them in the dashboard (for example `agent.labels.ha_core_version`):

`ha_os`, `ha_os_version`, `ha_core_version`, `ha_supervisor_version`, `ha_machine`,
`ha_arch`, `ha_channel`, `ha_app_version`. Add your own under **Custom labels**.

## Configuration reference

Every option can be set in the app's **Configuration** tab (list options in YAML mode).
Defaults are shown in the tab itself; the grouping below follows it.

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
| `ha_core_log_enabled` | Also read `/homeassistant/home-assistant.log` (already in the journal). |
| `log_files` | Extra log files: `path`, `format`, `only_future_events`, `ignore`, `restrict`, `exclude`, `age`. |
| `log_commands` | Command output as events: `command`, `format`, `frequency`, `alias`. |

### File integrity monitoring

| Option | Purpose |
| --- | --- |
| `fim_enabled`, `fim_frequency`, `fim_scan_on_start` | Turn it on, full-scan interval, scan at start. |
| `fim_directories` | Paths to watch: `path`, `realtime`, `report_changes`, `check_all`, `restrict`, `tags`, `recursion_level`. |
| `fim_ignore`, `fim_ignore_sregex` | Paths and patterns to leave out (defaults skip logs, databases, caches). |
| `fim_nodiff`, `fim_nodiff_sregex` | Paths whose **content is never sent** (default: `secrets.yaml`, `.storage`, `/ssl`). |
| `fim_max_eps`, `fim_process_priority`, `fim_file_limit` | Throttling, scanner priority, file cap. |
| `fim_sync_enabled`, `fim_sync_interval`, `fim_sync_max_eps` | Inventory synchronization with the manager. |

`fim_ignore_sregex` uses Wazuh's *simple* regular expressions: `^` and `$` anchor, `|` means
"or", and everything else, including `.`, matches literally.

### Rootkit checks, SCA and inventory

`rootcheck_*` toggle each check and its frequency. `sca_enabled`, `sca_interval`,
`sca_scan_on_start`, `sca_skip_nfs` and `sca_policies` control security configuration
assessment (list your own policy files in `sca_policies`). `inventory_*` toggle the
inventory sections and the interval.

### Response and advanced

| Option | Purpose |
| --- | --- |
| `active_response_enabled` | Let the manager run response scripts on the agent. Off: they would act on the app's container, not on Home Assistant OS. |
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
| `ossec_extra.conf` | Extra `<ossec_config>` blocks appended to the generated configuration. Use it for anything without an option. |
| `local_internal_options_extra.conf` | Extra lines appended to Wazuh's `local_internal_options.conf`. |
| `ossec.conf` | A complete configuration, used instead of the generated one when `use_custom_ossec_conf` is on. |
| Certificates, policies | Anything you reference by path: CA and agent certificates (`/config/ca.pem`), SCA policies (`/config/sca/home-assistant.yml`). |

Example `ossec_extra.conf`:

```xml
<ossec_config>
  <labels>
    <label key="room">basement</label>
  </labels>
</ossec_config>
```

## Security

### What the app can and cannot do

The app is built to keep Home Assistant's **security rating at its maximum**:

- **No extra privileges.** No host network, no published ports, no added Linux
  capabilities, no full access, no host PID namespace, no Docker API; protection mode stays
  on. The agent only makes **outbound** connections to your manager and exposes no port.
- **Security rating 8 of 8**, the maximum. Home Assistant shows 7 on the store page before the
  app is installed and 8 afterwards: it counts the custom AppArmor profile (below) only once
  the profile has been loaded on the host, which happens at install.
- **Read-only access** to the Home Assistant configuration (`/homeassistant`), certificates
  (`/ssl`) and its own configuration folder, and to the host journal.
- **Supervisor API: info calls only** (hostname and versions, used for the agent name and
  labels).
- **A status page that cannot change anything**: unprivileged, read-only, reachable only through
  Home Assistant's ingress gateway, and it never serves the agent's key.
- A **custom AppArmor profile**, and a **digest-pinned Debian base image**. The Wazuh agent
  is installed from Wazuh's official apt repository, and the build fails if the repository's
  signing key ever differs from the pinned fingerprint.

### Permissions, and how they were checked

Wazuh's documentation lists what an agent needs from the **network** (outbound 1514/tcp, or
UDP if chosen, to send events; outbound 1515/tcp to enroll) and nothing about Linux
capabilities. So the app does not guess: the test suite runs the agent against a real manager
with the capabilities cut down and checks that it still enrolls, connects, runs all five
daemons and reports healthy.

| Run | Result |
| --- | --- |
| Docker's default capabilities (what an app gets when it asks for none) | Works. |
| The default set minus `NET_RAW`, `AUDIT_WRITE`, `MKNOD`, `SETFCAP` (what current Supervisors remove) | Works. |
| Only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`, `KILL` | Works. |
| No capabilities at all | Does not run. |

Taking the defaults away one at a time showed that each of those six is needed (fixing file
ownership and modes, switching to the agent's own account, and signalling its daemons) and
that the other eight are not. The agent needs **no capability beyond what every app already
has**, which is why the app requests none and keeps the maximum security rating. Enrollment
needs nothing from Home Assistant either: the device registers itself with the manager the
way any Linux host does.

What the agent can then read is decided by the folders Home Assistant maps into the app
(configuration and certificates, read-only) and the host journal, as described above.

### What your Wazuh manager can do

An agent trusts its manager. The manager can push centralized configuration to this agent,
including extra files to monitor. The defaults limit the damage of a compromised or
mistaken manager: the content of `secrets.yaml`, `.storage` and `/ssl` is never sent
(`fim_nodiff*`), `allow_remote_commands` is off (so the manager cannot make the agent run
commands), and active response is off. Keep your manager patched and its enrollment
protected with a registration password.

### Secrets

The registration password is written to a file readable only by root and the agent's
account and is never written to the configuration file, the log or a command line. The
agent's key is stored in the app's persistent storage and is included in Home Assistant
backups: restore a backup only onto the device it came from, or two devices would claim
the same Wazuh identity.

### Monitoring the whole host

Reading the Home Assistant OS host's own filesystem, processes and network is not possible
for an app that keeps protection mode on. It is possible only for an *unprotected* app
(a user turns protection mode off) with extra privileges, which lowers the security rating
to its minimum and hands the app the ability to read or modify the whole system. This app
does not do that. If your goal is whole-host visibility, that would be a separate, clearly
labelled variant that requires disabling protection mode.

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
- **No journal events:** the app log says `Host journal found; using its machine ID...` when
  it sees the host journal. If it does not, the Supervisor is not mapping the journal; check
  that the app was updated to a version declaring `journald`.
- **File integrity "inotify" messages:** real-time watching is limited by the host's
  `fs.inotify.max_user_watches`. Watch fewer directories in real time, or set
  `realtime: false` for large ones.
- **Several Home Assistant installations:** give each its own `agent_name`.
- **Check the generated configuration:** it is rewritten at every start; compare with your
  options if something is not applied.
