# Builds the render context from the app options and runtime info.
#
# Run as:  jq -n --slurpfile o options.json --slurpfile i info.json -f ctx.jq
#
# $o  the options the Supervisor wrote to /data/options.json
# $i  runtime facts: the Supervisor's /info (hostname, operating_system, ...),
#     plus app_version and journal_available which the init script adds.
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
      ca_path:       (opt("enrollment_ca_path"; "") | trim),
      certificate_path: (opt("enrollment_certificate_path"; "") | trim),
      key_path:      (opt("enrollment_key_path"; "") | trim),
      use_password:  (opt("enrollment_password"; "") | present),
      use_source_ip: (opt("enrollment_use_source_ip"; false) | yn),
      delay:         opt("enrollment_delay"; 20)
    },

    buffer: {
      disabled:           (opt("buffer_enabled"; true) | not | yn),
      queue_size:         opt("buffer_queue_size"; 5000),
      events_per_second:  opt("buffer_events_per_second"; 500)
    },

    labels: labels,

    journal: { localfiles: journal_localfiles },

    files: (
      [ (if opt("ha_core_log_enabled"; false) then
           {path: "/homeassistant/home-assistant.log", format: "syslog"}
         else empty end) ]
      + (opt("log_files"; [])
         | map({path: (.path | trim), format: (.format // "syslog"),
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
      check_if:     (opt("rootcheck_check_if"; true) | yn)
    },

    sca: {
      enabled:       (opt("sca_enabled"; false) | yn),
      scan_on_start: (opt("sca_scan_on_start"; true) | yn),
      interval:      opt("sca_interval"; "12h"),
      skip_nfs:      (opt("sca_skip_nfs"; true) | yn),
      policies:      (opt("sca_policies"; []) | nonblank)
    },

    inventory: {
      disabled:      (opt("inventory_enabled"; true) | not | yn),
      interval:      opt("inventory_interval"; "1h"),
      scan_on_start: (opt("inventory_scan_on_start"; true) | yn),
      hardware:      (opt("inventory_hardware"; true) | yn),
      os:            (opt("inventory_os"; true) | yn),
      network:       (opt("inventory_network"; true) | yn),
      packages:      (opt("inventory_packages"; false) | yn),
      ports:         (opt("inventory_ports"; false) | yn),
      processes:     (opt("inventory_processes"; false) | yn)
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
      directories:   (opt("fim_directories"; default_fim_directories)
                      | map({path: (.path | trim),
                             realtime: ((.realtime // false) | yn),
                             report_changes: ((.report_changes // false) | yn),
                             check_all: ((if .check_all == null then true else .check_all end) | yn),
                             restrict: (.restrict // ""), tags: (.tags // ""),
                             recursion_level: .recursion_level})),
      ignore:         opt("fim_ignore"; []),
      ignore_sregex:  opt("fim_ignore_sregex"; default_fim_ignore_sregex),
      nodiff:         opt("fim_nodiff"; default_fim_nodiff),
      nodiff_sregex:  opt("fim_nodiff_sregex"; default_fim_nodiff_sregex)
    },

    active_response: { disabled: (opt("active_response_enabled"; false) | not | yn) },

    options_file: {
      debug_level:     opt("debug_level"; 0),
      remote_commands: (if opt("allow_remote_commands"; false) then 1 else 0 end)
    }
  }
