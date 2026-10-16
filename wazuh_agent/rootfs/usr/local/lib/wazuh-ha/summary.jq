# Builds summary.json: the non-secret description of this agent that the status page shows.
#
#   jq -n --slurpfile c context.json --slurpfile i info.json -f summary.jq
#
# Nothing secret goes in here: the registration password, the certificate paths' contents and the
# agent key never appear, only whether a password or certificate verification is configured.

$c[0] as $c
| $i[0] as $i
| def enabled($disabled): $disabled == "no";
  def yes: . == "yes";

  {
    agent: {
      name: $c.enrollment.agent_name,
      groups: ($c.enrollment.groups | if . == "" then [] else split(",") end),
      config_profile: $c.client.config_profile,
      version: ""
    },
    manager: {
      addresses: ([$c.servers[].address] | unique),
      port: ($c.servers[0].port // 1514),
      protocol: ($c.servers[0].protocol // "tcp"),
      enrollment: {
        enabled: ($c.enrollment.enabled | yes),
        address: $c.enrollment.address,
        port: $c.enrollment.port,
        password_set: $c.enrollment.use_password,
        verified: ($c.enrollment.ca_path != "")
      }
    },
    modules: {
      fim: enabled($c.fim.disabled),
      journal: (($c.journal.localfiles | length) > 0),
      inventory: enabled($c.inventory.disabled),
      rootcheck: enabled($c.rootcheck.disabled),
      sca: ($c.sca.enabled | yes),
      active_response: enabled($c.active_response.disabled),
      remote_commands: ($c.options_file.remote_commands == 1)
    },
    host: {
      # Where the agent runs: "host" is the Home Assistant OS device itself, "container" this app's own.
      scope: ($i.host.mode // "container"),
      hostname: ($i.hostname // null),
      operating_system: ($i.operating_system // null),
      os_version: ($i.hassos // null),
      core_version: ($i.homeassistant // null),
      supervisor_version: ($i.supervisor // null),
      machine: ($i.machine // null),
      arch: ($i.arch // null),
      channel: ($i.channel // null)
    },
    app: { version: ($i.app_version // null) }
  }
