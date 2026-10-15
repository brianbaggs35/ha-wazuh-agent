# Validates the app options before anything is rendered.
#
# Run as:  jq -n -r --slurpfile o options.json --slurpfile i info.json -f validate.jq
# Output:  one human-readable error per line; no output means the options are valid.
#
# Why this exists: Wazuh's ossec.conf parser is not a normal XML parser. It does
# not decode entities (&lt; stays "&lt;" inside a value), so values are written
# out verbatim, and a literal "<" or a newline inside a value corrupts the file.
# A value ending in an odd number of backslashes escapes the closing tag. Rather
# than silently mangling user input, reject it here with a message that names the
# offending option.

$o[0] as $o
| def opt($k; $d): if $o[$k] == null then $d else $o[$k] end;
  def blank: . == null or (tostring | gsub("^\\s+|\\s+$"; "") | length) == 0;
  def trailing_backslash: test("(^|[^\\\\])(\\\\\\\\)*\\\\$");

  # Anything that is written into ossec.conf must be free of characters the
  # Wazuh XML reader cannot represent. The enrollment password goes to a file,
  # not into XML, so only newlines matter there.
  [ paths(type == "string") as $p
    | ($o | getpath($p)) as $v
    | ($p | map(tostring) | join(".")) as $name
    | if $p[0] == "enrollment_password" then
        (if ($v | test("[\\n\\r\\u0000]")) then "\($name): must not contain a line break" else empty end)
      else
        (if ($v | test("<")) then "\($name): the character \"<\" is not supported (Wazuh does not decode XML entities); use the extra configuration file instead"
         elif ($v | test("[\\n\\r\\u0000]")) then "\($name): must be a single line"
         elif ($v | trailing_backslash) then "\($name): must not end with a single backslash"
         else empty end)
      end
  ][],

  (if ($o.use_custom_ossec_conf // false) | not then
     (if (opt("manager_address"; "") | blank) then
        "manager_address: required. Set it to the IP address or hostname of your Wazuh manager"
      else empty end)
   else empty end),

  (if ((opt("manager_address"; "") | blank) | not) and (opt("manager_address"; "") | test("[\\s,]")) then
     "manager_address: must be a single host name or IP address (use manager_failover_addresses for more)"
   else empty end),

  (opt("manager_failover_addresses"; []) | to_entries[]
    | select(.value | test("[\\s,]") or blank)
    | "manager_failover_addresses[\(.key)]: must be a single, non-empty host name or IP address"),

  (if (opt("agent_name"; "") | blank | not) and (opt("agent_name"; "") | test("^[A-Za-z0-9._-]{2,}$") | not) then
     "agent_name: at least 2 characters, letters, digits, \"-\", \"_\" and \".\" only"
   else empty end),

  (opt("agent_groups"; []) | to_entries[]
    | select(.value | test("^[A-Za-z0-9._-]+$") | not)
    | "agent_groups[\(.key)]: letters, digits, \"-\", \"_\" and \".\" only"),

  (opt("agent_labels"; []) | to_entries[]
    | select(.value.key | test("^[A-Za-z0-9_.@-]+$") | not)
    | "agent_labels[\(.key)].key: letters, digits, \"-\", \"_\", \".\" and \"@\" only"),

  (if ((opt("enrollment_certificate_path"; "") | blank) != (opt("enrollment_key_path"; "") | blank)) then
     "enrollment_certificate_path and enrollment_key_path must be set together"
   else empty end),

  (opt("fim_directories"; []) | to_entries[]
    | (if (.value.path | startswith("/") | not) then "fim_directories[\(.key)].path: must be an absolute path" else empty end),
      (if (.value.path | test(",")) then "fim_directories[\(.key)].path: must not contain a comma" else empty end),
      (if ((.value.restrict // "") | test("[\"']")) then "fim_directories[\(.key)].restrict: must not contain quotes" else empty end),
      (if ((.value.tags // "") | test("[\"']")) then "fim_directories[\(.key)].tags: must not contain quotes" else empty end)),

  (opt("log_files"; []) | to_entries[]
    | select(.value.path | blank)
    | "log_files[\(.key)].path: required"),

  (opt("log_commands"; []) | to_entries[]
    | select(.value.command | blank)
    | "log_commands[\(.key)].command: required"),

  (opt("journal_filters"; []) | to_entries[]
    | select((.value.field | test("^[A-Z_][A-Z0-9_]*$") | not))
    | "journal_filters[\(.key)].field: a journald field name such as SYSLOG_IDENTIFIER or PRIORITY"),

  (if (opt("sca_interval"; "12h") | test("^[0-9]+[smhdwM]$") | not) then
     "sca_interval: a number followed by s, m, h, d, w or M (for example 12h)" else empty end),

  (if (opt("inventory_interval"; "1h") | test("^[0-9]+[smhdwM]$") | not) then
     "inventory_interval: a number followed by s, m, h, d, w or M (for example 1h)" else empty end),

  (if (opt("fim_sync_interval"; "5m") | test("^[0-9]+[smhd]$") | not) then
     "fim_sync_interval: a number followed by s, m, h or d (for example 5m)" else empty end)
