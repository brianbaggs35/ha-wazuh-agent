# Wazuh Agent for Home Assistant

Adds your Home Assistant OS device to your existing [Wazuh](https://wazuh.com) deployment
as a monitored endpoint.

Give it the address of your Wazuh manager and start it: the agent enrolls itself and
shows up under **Agents** in the Wazuh dashboard, where its alerts sit next to the rest
of your endpoints.

## What gets monitored

- **Host and Home Assistant logs** from the OS journal: SSH logins, `sudo`, kernel
  warnings, Home Assistant Core (including failed web logins), the Supervisor and errors
  from any app.
- **File integrity** of your Home Assistant configuration and certificates, in real time.
- **System inventory** (hardware, operating system, network), **rootkit checks**, and
  optional **configuration assessment** with your own policies.
- Any **log file or command output** you add.

## Why it is safe to run

The app asks for **no extra privileges**: no host network, no open ports, no added
capabilities, no full access, protection mode stays on. It only makes outbound
connections to your manager. See the *Security* section of the documentation for exactly
what it can and cannot see.

## Getting started

Open the **Documentation** tab for the full guide. In short:

1. Allow ports **1514/tcp** and **1515/tcp** from this device to your Wazuh manager.
2. Set **Wazuh manager address** in the Configuration tab (and a registration password if
   your manager requires one).
3. Start the app and check the **Log** tab for `Connected to the server`.
