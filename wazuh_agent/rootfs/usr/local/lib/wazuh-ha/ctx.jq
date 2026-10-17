# Builds the render context from the app options and runtime info.
#
# Run as:  jq -n --slurpfile o options.json --slurpfile i info.json -f ctx.jq
#
# $o  the options the Supervisor wrote to /data/options.json
# $i  runtime facts: the Supervisor's /info (hostname, operating_system, ...),
#     plus app_version and journal_available, and host (the scope the agent runs in and, for the
#     Home Assistant OS host, where the app's folders are on it), which the init script adds.
#
# Every option falls back to the same default config.yaml declares, so a
# partial options file still renders. tests/ checks the two never drift apart.
#
# The enrollment password is deliberately NOT copied into the context: it is
# written straight to etc/authd.pass by the init script and never appears in
# ossec.conf or in any intermediate file.

$o[0] as $o
| $i[0] as $i
| def opt($k; $d): if $o[$k] == null then $d else $o[$k] end;
  def yn: if . then "yes" else "no" end;
  def trim: gsub("^\\s+|\\s+$"; "");
  def present: . != null and ((tostring | trim | length) > 0);
  def nonblank: map(select(present) | tostring | trim);

  # Where the agent runs. "host": in the Home Assistant OS host's own file system, as if it had been
  # installed on the device. Anything else: inside this app's container.
  def host_mode: ($i.host.mode // "container") == "host";

  # Whether the app's own configuration assessment policy for the device is wanted: on the device, unless the option
  # says no. It does not depend on sca_enabled, which a user may have saved as false before the app had a policy
  # of its own (the Supervisor keeps what was saved), and which stays the switch of the user's own policies.
  def host_policy: host_mode and opt("sca_host_policy"; true);

  # A path as the agent will see it. The folders Home Assistant maps into the app (/homeassistant,
  # /config, /ssl, /share, ...) are at other places on the host, so the paths in the options, which
  # are written the way the app sees them, are turned into the host's. The deepest folder that
  # contains the path wins; a path outside all of them (/etc, /mnt/boot) is the host's already.
  def tr_path:
    if host_mode then
      . as $p
      | ([($i.host.mounts // {}) | to_entries[]
          | . as $e
          | select($p == $e.key or ($p | startswith($e.key + "/")))]
         | sort_by(.key | length) | last) as $m
      | if $m == null then $p else $m.value + ($p | ltrimstr($m.key)) end
    else . end;

  # The same for the simple regular expressions of the file integrity options, which may be anchored
  # at a folder ("^/homeassistant/.storage/").
  def tr_regex:
    if host_mode and startswith("^/") then "^" + (.[1:] | tr_path) else . end;

  def agent_name:
    (opt("agent_name"; "") | trim) as $n
    | if ($n | length) > 0 then $n
      else (($i.hostname // "homeassistant") | gsub("[^A-Za-z0-9._-]"; "-")) as $h
        | if ($h | length) < 2 then "ha-" + $h else $h end
      end;

  # Labels describing the Home Assistant host, so the Wazuh dashboard can be
  # filtered by OS version, Core version and so on. User labels win on a clash.
  def auto_labels:
    if opt("auto_labels"; true) then
      [ {key: "ha_os",                value: $i.operating_system},
        {key: "ha_os_version",        value: $i.hassos},
        {key: "ha_core_version",      value: $i.homeassistant},
        {key: "ha_supervisor_version", value: $i.supervisor},
        {key: "ha_machine",           value: $i.machine},
        {key: "ha_arch",              value: $i.arch},
        {key: "ha_channel",           value: $i.channel},
        {key: "ha_app_version",       value: $i.app_version} ]
      | map(select(.value != null and (.value | tostring | length) > 0) | .value |= tostring)
    else [] end;

  def labels:
    (auto_labels + (opt("agent_labels"; []) | map(select(.key | present))))
    | reduce .[] as $l ({}; .[$l.key] = $l.value)
    | to_entries | map({key, value});

  # Host journal presets. Identifiers come from the Supervisor itself:
  # Core logs as "homeassistant", the Supervisor as "hassio_supervisor", each
  # app as "addon_<slug>"; the OS services are listed in its identifier table.
  def journal_localfiles:
    if (opt("journal_enabled"; true) | not) or ($i.journal_available == false) then []
    elif opt("journal_all"; false) then [{filters: []}]
    else
      [ (if opt("journal_auth"; true) then
           {filters: [{field: "SYSLOG_IDENTIFIER", pattern: "^(sshd|sshd-session|dropbear|sudo|su|login|systemd-logind)$"}]}
         else empty end),
        (if opt("journal_kernel"; true) then
           {filters: [{field: "_TRANSPORT", pattern: "^kernel$"}, {field: "PRIORITY", pattern: "^[0-4]$"}]}
         else empty end),
        (if opt("journal_homeassistant"; true) then
           {filters: [{field: "SYSLOG_IDENTIFIER", pattern: "^homeassistant$"}]}
         else empty end),
        (if opt("journal_supervisor"; true) then
           {filters: [{field: "SYSLOG_IDENTIFIER", pattern: "^hassio_supervisor$"}]}
         else empty end),
        (if opt("journal_errors"; true) then
           {filters: [{field: "PRIORITY", pattern: "^[0-3]$"}]}
         else empty end),
        (if opt("journal_apps"; false) then
           {filters: [{field: "SYSLOG_IDENTIFIER", pattern: "^addon_"}]}
         else empty end) ]
      + (opt("journal_filters"; [])
         | map({filters: [{field: .field, pattern: .pattern, ignore_if_missing: (.ignore_if_missing // false)}]}))
    end;

  def default_fim_directories:
    [ {path: "/homeassistant", realtime: true,  report_changes: false},
      {path: "/ssl",           realtime: true,  report_changes: false} ];

  def default_fim_ignore_sregex:
    [ ".log$", ".log.1$", ".db$", ".db-wal$", ".db-shm$",
      "/.storage/core.restore_state", "/.storage/trace.saved_traces",
      "/deps/", "/tts/", "/__pycache__/", ".pyc$" ];

  def default_fim_nodiff:        [ "/homeassistant/secrets.yaml" ];
  def default_fim_nodiff_sregex: [ "^/homeassistant/.storage/", "^/ssl/" ];

  # What a Wazuh agent monitors on a Linux machine out of the box (the package's own ossec.conf:
  # /etc, /usr/bin, /usr/sbin, /bin, /sbin, /boot, with the same ignores and no content for the
  # password files), plus what matters on Home Assistant OS: the boot partition, where the SSH
  # keys of the debug login live (CONFIG/authorized_keys), root's own SSH keys, and the apps you
  # wrote yourself. These are paths of the host.
  def host_fim_directories:
    [ {path: "/etc",                           realtime: true,  report_changes: false},
      {path: "/root/.ssh",                     realtime: true,  report_changes: false},
      {path: "/mnt/boot",                      realtime: true,  report_changes: false},
      {path: "/mnt/data/supervisor/addons/local", realtime: true, report_changes: false},
      {path: "/usr/bin",                       realtime: false, report_changes: false},
      {path: "/usr/sbin",                      realtime: false, report_changes: false},
      {path: "/bin",                           realtime: false, report_changes: false},
      {path: "/sbin",                          realtime: false, report_changes: false} ];
  def host_fim_ignore:
    [ "/etc/mtab", "/etc/hosts.deny", "/etc/mail/statistics", "/etc/random-seed", "/etc/random.seed",
      "/etc/adjtime", "/etc/httpd/logs", "/etc/utmpx", "/etc/wtmpx", "/etc/cups/certs", "/etc/dumpdates",
      "/etc/svc/volatile", "/etc/resolv.conf" ];
  def host_fim_ignore_sregex: [ ".swp$" ];
  def host_fim_nodiff:        [ "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-" ];
  def host_fim_nodiff_sregex: [ "^/etc/ssl/private/", "^/etc/pki/tls/private/" ];
  def with_host_defaults($user; $defaults):
    if host_mode and opt("fim_host_defaults"; true) then $user + ($defaults - $user) else $user end;

  ( (opt("manager_address"; "") | trim) as $primary
    | ([$primary] + (opt("manager_failover_addresses"; []) | map(trim)) | map(select(length > 0)))
  ) as $addresses

| {
    servers: [ $addresses[] | {address: ., port: opt("manager_port"; 1514), protocol: opt("manager_protocol"; "tcp")} ],

    client: {
      max_retries:    opt("server_max_retries"; 5),
      retry_interval: opt("server_retry_interval"; 10),
      notify_time:    opt("notify_time"; 20),
      time_reconnect: opt("time_reconnect"; 60),
      auto_restart:   (opt("auto_restart"; true) | yn),
      crypto_method:  opt("crypto_method"; "aes"),
      config_profile: (opt("config_profile"; "homeassistant") | trim)
    },

    enrollment: {
      enabled:       (opt("enrollment_enabled"; true) | yn),
      address:       (opt("enrollment_address"; "") | trim),
      port:          opt("enrollment_port"; 1515),
      agent_name:    agent_name,
      groups:        (opt("agent_groups"; []) | nonblank | join(",")),
      ca_path:       (opt("enrollment_ca_path"; "") | trim | tr_path),
      certificate_path: (opt("enrollment_certificate_path"; "") | trim | tr_path),
      key_path:      (opt("enrollment_key_path"; "") | trim | tr_path),
      use_password:  (opt("enrollment_password"; "") | present),
      use_source_ip: (opt("enrollment_use_source_ip"; false) | yn),
      delay:         opt("enrollment_delay"; 20)
    },

    buffer: {
      disabled:           (opt("buffer_enabled"; true) | not | yn),
      queue_size:         opt("buffer_queue_size"; 5000),
      events_per_second:  opt("buffer_events_per_second"; 500)
    },

    host: { enabled: host_mode },

    labels: labels,

    journal: { localfiles: journal_localfiles },

    files: (
      [ (if opt("ha_core_log_enabled"; false) then
           {path: ("/homeassistant/home-assistant.log" | tr_path), format: "syslog"}
         else empty end) ]
      + (opt("log_files"; [])
         | map({path: (.path | trim | tr_path), format: (.format // "syslog"),
                ignore: (.ignore // ""), restrict: (.restrict // ""),
                exclude: (.exclude // ""), age: (.age // ""),
                only_future_events: (if .only_future_events == null then true else .only_future_events end | yn)}))
    ),

    commands: (opt("log_commands"; [])
      | map({command: (.command | trim), format: (.format // "full_command"),
             frequency: (.frequency // 360), alias: (.alias // "")})),

    rootcheck: {
      disabled:     (opt("rootcheck_enabled"; true) | not | yn),
      frequency:    opt("rootcheck_frequency"; 43200),
      check_files:  (opt("rootcheck_check_files"; true) | yn),
      check_trojans: (opt("rootcheck_check_trojans"; true) | yn),
      check_dev:    (opt("rootcheck_check_dev"; true) | yn),
      check_sys:    (opt("rootcheck_check_sys"; true) | yn),
      check_pids:   (opt("rootcheck_check_pids"; false) | yn),
      check_ports:  (opt("rootcheck_check_ports"; false) | yn),
      check_if:     (opt("rootcheck_check_if"; true) | yn),
      # Left out of the scans, as in the package's own configuration: other containers' storage. On
      # Home Assistant OS that, and everything else the apps keep, lives under /mnt/data.
      ignore:       (if host_mode then ["/var/lib/containerd", "/var/lib/docker/overlay2", "/mnt/data"] else [] end)
    },

    sca: {
      # The app's own policy (home_assistant_os.yml) is written by wazuh-ha-render, which asks host_policy, and put next
      # to the agent's files by wazuh-ha-init. It alone starts the assessment; the user's policies run only with sca_enabled.
      host_policy:   host_policy,
      enabled:       ((opt("sca_enabled"; false) or host_policy) | yn),
      scan_on_start: (opt("sca_scan_on_start"; true) | yn),
      interval:      opt("sca_interval"; "12h"),
      skip_nfs:      (opt("sca_skip_nfs"; true) | yn),
      policies:      ((if host_policy then ["ruleset/ha/home_assistant_os.yml"] else [] end)
                      + (if opt("sca_enabled"; false) then (opt("sca_policies"; []) | nonblank | map(tr_path)) else [] end))
    },

    inventory: {
      disabled:      (opt("inventory_enabled"; true) | not | yn),
      interval:      opt("inventory_interval"; "1h"),
      scan_on_start: (opt("inventory_scan_on_start"; true) | yn),
      hardware:      (opt("inventory_hardware"; true) | yn),
      os:            (opt("inventory_os"; true) | yn),
      network:       (opt("inventory_network"; true) | yn),
      # On the host the packages of Home Assistant Core are what vulnerability detection can use (see
      # core_python in wazuh-ha-host), so they are wanted unless the option says no; a Linux host's own
      # (dpkg, rpm) are in the inventory as soon as the packages switch is on.
      packages:      ((opt("inventory_packages"; false) or (host_mode and opt("inventory_core_packages"; true))) | yn),
      # In the host's file system these describe the device, not a container, and are what a Wazuh agent
      # reports on any Linux machine: one switch for processes, listening ports, users, groups and
      # services. In the container the old options still decide, and users, groups and services stay off.
      ports:         ((if host_mode then opt("inventory_host_details"; true) else opt("inventory_ports"; false) end) | yn),
      processes:     ((if host_mode then opt("inventory_host_details"; true) else opt("inventory_processes"; false) end) | yn),
      users:         ((host_mode and opt("inventory_host_details"; true)) | yn),
      groups:        ((host_mode and opt("inventory_host_details"; true)) | yn),
      services:      ((host_mode and opt("inventory_host_details"; true)) | yn)
    },

    fim: {
      disabled:      (opt("fim_enabled"; true) | not | yn),
      frequency:     opt("fim_frequency"; 43200),
      scan_on_start: (opt("fim_scan_on_start"; true) | yn),
      max_eps:       opt("fim_max_eps"; 50),
      process_priority: opt("fim_process_priority"; 10),
      file_limit:    opt("fim_file_limit"; 100000),
      sync_enabled:  (opt("fim_sync_enabled"; true) | yn),
      sync_interval: opt("fim_sync_interval"; "5m"),
      sync_max_eps:  opt("fim_sync_max_eps"; 10),
      directories:   (( opt("fim_directories"; default_fim_directories)
                        | map({path: (.path | trim | tr_path), realtime: (.realtime // false),
                               report_changes: (.report_changes // false),
                               check_all: (if .check_all == null then true else .check_all end),
                               restrict: (.restrict // ""), tags: (.tags // ""),
                               recursion_level: .recursion_level}) ) as $user
                      | ($user | map(.path)) as $taken
                      | $user + (if host_mode and opt("fim_host_defaults"; true)
                                 then (host_fim_directories | map(select(.path as $p | $taken | index($p) | not)
                                         | . + {check_all: true, restrict: "", tags: "", recursion_level: null}))
                                 else [] end)
                      | map(. + {realtime: (.realtime | yn), report_changes: (.report_changes | yn), check_all: (.check_all | yn)})),
      ignore:         with_host_defaults(opt("fim_ignore"; []) | map(tr_path); host_fim_ignore),
      ignore_sregex:  with_host_defaults(opt("fim_ignore_sregex"; default_fim_ignore_sregex) | map(tr_regex); host_fim_ignore_sregex),
      nodiff:         with_host_defaults(opt("fim_nodiff"; default_fim_nodiff) | map(tr_path); host_fim_nodiff),
      nodiff_sregex:  with_host_defaults(opt("fim_nodiff_sregex"; default_fim_nodiff_sregex) | map(tr_regex); host_fim_nodiff_sregex)
    },

    active_response: { disabled: (opt("active_response_enabled"; false) | not | yn) },

    options_file: {
      debug_level:     opt("debug_level"; 0),
      remote_commands: (if opt("allow_remote_commands"; false) then 1 else 0 end)
    }
  }
