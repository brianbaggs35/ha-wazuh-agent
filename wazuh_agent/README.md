# Wazuh Agent for Home Assistant

The [Wazuh](https://wazuh.com) agent of your Home Assistant OS device. Installing this app does what
installing the Wazuh agent on the device would do, which Home Assistant OS does not allow: the device
is enrolled in your existing Wazuh deployment and monitored like any other endpoint, by its own
address, operating system, processes, files and logs.

Give it the address of your Wazuh manager and start it: the agent enrolls itself and
shows up under **Agents** in the Wazuh dashboard, where its alerts sit next to the rest
of your endpoints.

**Turn Protection mode off** on this app's Info tab first: reaching the device takes more access than
a protected app has.

## What gets monitored

- **The device's logs** from the OS journal: SSH logins, `sudo`, kernel warnings, Home Assistant Core
  (including failed web logins), the Supervisor and errors from any app.
- **File integrity** of your Home Assistant configuration and certificates, the device's `/etc` and
  binaries, the boot partition and root's SSH keys.
- **System inventory** of the device (hardware including the CPU, operating system, network and its
  real address, processes, listening ports, accounts and services, and the Python packages Home
  Assistant Core runs on), **rootkit checks**, and **configuration assessment** with your own policies.
- Any **log file or command output** you add.

## A status page in the sidebar

Turn on **Show in sidebar** and a **Wazuh Agent** panel appears: whether the agent is running and
connected, who it is registered as, what it monitors, whether a newer agent exists, a connection
test and the agent's log. It is read-only.

## Why the security rating is low

To be the agent of the device and not of a container, the app asks Home Assistant for the device's
process namespace, network and host name and two Linux capabilities, and Home Assistant rates that
low. It does not ask for full access, the Docker API or published ports, and only makes outbound
connections to your manager. See the *Security* section of the documentation for what each permission
is for and what the app does with it.

## Getting started

Open the **Documentation** tab for the full guide. In short:

1. Allow ports **1514/tcp** and **1515/tcp** from this device to your Wazuh manager.
2. Turn **Protection mode** off on the Info tab.
3. Set **Wazuh manager address** in the Configuration tab (and a registration password if
   your manager requires one).
4. Start the app and check the **Log** tab for `Connected to the server`.

*Wazuh is a trademark of Wazuh, Inc. This app is an independent project: it is not affiliated with,
endorsed by or sponsored by Wazuh, Inc.*
