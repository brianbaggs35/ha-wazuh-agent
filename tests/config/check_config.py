"""Static checks on the app definition. No Docker needed.

    python3 -I tests/config/check_config.py

What it guards:
  * every option has a default that satisfies its own schema, and a UI translation
  * the privileges the app asks for are exactly the reviewed list that lets the agent monitor the
    Home Assistant OS host (and so the security rating is the one that list gives)
  * versions, the pinned base image and the pinned Wazuh signing key are consistent
  * the app's own SCA policy is a policy Wazuh can load: its structure, unique IDs in the app's range, and rules
    in the syntax Wazuh reads (a typo here is otherwise found by the agent, at run time, on a device)
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = ROOT / "wazuh_agent"

# The app is the Wazuh agent of the Home Assistant OS device itself, so it asks for access to the host: its process
# namespace, network and host name, and the capabilities to enter its file system. That is what the
# rating below pays for, and DOCS.md says so. Anything beyond this list is a decision to make in a pull request,
# with a reason: change the list and the number together.
HOST_ACCESS = {"host_network": True, "host_pid": True, "host_uts": True}
PRIVILEGED = {"SYS_ADMIN", "SYS_PTRACE"}
# 5, +1 AppArmor profile, +2 ingress; -1 for the privileged capabilities, -1 host_network, -2 host_pid,
# and -1 for host_uts together with SYS_ADMIN.
MINIMUM_RATING = 3

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def load_yaml(path: pathlib.Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- schema
def is_optional(rule) -> bool:
    return isinstance(rule, str) and rule.endswith("?")


def validate(value, rule, where: str) -> None:
    """Check one value against a Supervisor schema rule (the subset this app uses)."""
    if isinstance(rule, list):
        if not isinstance(value, list):
            err(f"{where}: expected a list, got {type(value).__name__}")
            return
        item_rule = rule[0]
        for index, item in enumerate(value):
            if isinstance(item_rule, dict):
                if not isinstance(item, dict):
                    err(f"{where}[{index}]: expected a mapping")
                    continue
                for key in item:
                    if key not in item_rule:
                        err(f"{where}[{index}].{key}: not in the schema")
                for key, sub in item_rule.items():
                    if key in item:
                        validate(item[key], sub, f"{where}[{index}].{key}")
                    elif not is_optional(sub):
                        err(f"{where}[{index}].{key}: required")
            else:
                validate(item, item_rule, f"{where}[{index}]")
        return

    rule = rule[:-1] if is_optional(rule) else rule
    if rule == "str":
        ok = isinstance(value, str)
    elif rule == "password":
        ok = isinstance(value, str)
    elif rule == "bool":
        ok = isinstance(value, bool)
    elif rule == "port":
        ok = isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535
    elif m := re.fullmatch(r"int\((-?\d+)?,(-?\d+)?\)", rule):
        low, high = m.group(1), m.group(2)
        ok = isinstance(value, int) and not isinstance(value, bool)
        ok = ok and (low is None or value >= int(low)) and (high is None or value <= int(high))
    elif m := re.fullmatch(r"match\((.*)\)", rule):
        ok = isinstance(value, str) and re.search(m.group(1), value) is not None
    elif m := re.fullmatch(r"list\((.*)\)", rule):
        ok = value in m.group(1).split("|")
    else:
        err(f"{where}: unsupported schema rule {rule!r} (extend check_config.py)")
        return
    if not ok:
        err(f"{where}: {value!r} does not satisfy {rule!r}")


def check_options(config: dict, translations: dict) -> None:
    schema, options = config["schema"], config["options"]

    for key in options:
        if key not in schema:
            err(f"options.{key}: not in the schema")
    for key, rule in schema.items():
        if key in options:
            validate(options[key], rule, key)
        elif not is_optional(rule):
            err(f"schema.{key}: required but has no default in options")

    described = translations.get("configuration", {})
    for key, rule in schema.items():
        entry = described.get(key)
        if not entry:
            err(f"translations/en.yaml: no entry for option {key}")
            continue
        for field in ("name", "description"):
            if not str(entry.get(field, "")).strip():
                err(f"translations/en.yaml: {key} has no {field}")
        if isinstance(rule, list) and isinstance(rule[0], dict):
            fields = entry.get("fields", {})
            for sub in rule[0]:
                if sub not in fields:
                    err(f"translations/en.yaml: {key}.fields has no entry for {sub}")
                elif not all(str(fields[sub].get(f, "")).strip() for f in ("name", "description")):
                    err(f"translations/en.yaml: {key}.fields.{sub} needs a name and a description")
            for sub in fields:
                if sub not in rule[0]:
                    err(f"translations/en.yaml: {key}.fields.{sub} is not in the schema")
    for key in described:
        if key not in schema:
            err(f"translations/en.yaml: {key} is not an option")


# --------------------------------------------------------------------------- rating
RISKY_CAPABILITIES = {
    "BPF", "CHECKPOINT_RESTORE", "DAC_READ_SEARCH", "NET_ADMIN", "NET_RAW",
    "PERFMON", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO",
}


def security_rating(config: dict, has_profile: bool) -> int:
    """The Supervisor's rating_security() (supervisor/apps/utils.py), applied to config.yaml."""
    rating = 5
    if config.get("apparmor") is False:
        rating -= 1
    elif has_profile:
        rating += 1

    host_network = bool(config.get("host_network", False))
    published = any(port is not None for port in (config.get("ports") or {}).values())
    if config.get("ingress"):
        rating += 2
    elif not host_network and not published:
        rating += 2
    elif config.get("auth_api"):
        rating += 1

    privileged = set(config.get("privileged") or [])
    if privileged & RISKY_CAPABILITIES or config.get("kernel_modules"):
        rating -= 1
    rating -= {"manager": 1, "admin": 2}.get(config.get("hassio_role", "default"), 0)
    if host_network:
        rating -= 1
    if config.get("host_pid"):
        rating -= 2
    if config.get("host_uts") and "SYS_ADMIN" in privileged:
        rating -= 1
    if config.get("docker_api") or config.get("full_access"):
        rating = 1
    return max(min(8, rating), 1)


def check_security(config: dict) -> None:
    profile = APP / "apparmor.txt"
    has_profile = profile.is_file()
    if not has_profile:
        err("apparmor.txt is missing (worth +1 on the security rating)")
    else:
        match = re.search(r"^profile\s+(\S+)\s", profile.read_text(encoding="utf-8"), re.MULTILINE)
        if not match or match.group(1) != config["slug"]:
            err(f"apparmor.txt: the profile name must equal the slug {config['slug']!r}")

    rating = security_rating(config, has_profile)
    if rating < MINIMUM_RATING:
        err(f"security rating is {rating}, below the required {MINIMUM_RATING}")

    for key, value in HOST_ACCESS.items():
        if config.get(key) is not value:
            err(f"config.yaml must set {key}: {value}: the agent monitors the host, not its own container")
    if set(config.get("privileged") or []) != PRIVILEGED:
        err(f"privileged must be exactly {sorted(PRIVILEGED)}: SYS_PTRACE to read the host's namespaces, "
            "SYS_ADMIN to enter its mount namespace")
    for key in ("full_access", "docker_api", "host_ipc", "host_dbus", "kernel_modules", "devices", "usb", "uart",
                "gpio", "ports"):
        if config.get(key):
            err(f"config.yaml sets {key}: the app does not need it, and it would cost more than the reviewed "
                "access (see the security notes in DOCS.md)")
    if config.get("hassio_role", "default") != "default":
        err("hassio_role must stay 'default': the app only reads Supervisor info")
    if config.get("apparmor") is False:
        err("apparmor must not be disabled")
    # s6-overlay cannot run in the host's process namespace (Home Assistant documents this), so the app
    # supervises itself; Docker's own init stays on.
    if config.get("init") is False:
        err("init must not be false: the app has no s6-overlay, and relies on Docker's init")
    # The app shares the host's network, where a fixed ingress port could already be in use.
    if config.get("ingress_port") != 0:
        err("ingress_port must be 0 (the Supervisor assigns it), because the app is on the host network")
    # The status page: an ingress panel named "Wazuh Agent". Ingress is the one thing that must be
    # on; a published port would cost the rating, and is forbidden above.
    if config.get("ingress") is not True:
        err("ingress must be on: it is how the Wazuh Agent panel is shown")
    if config.get("panel_title") != "Wazuh Agent":
        err("panel_title must be 'Wazuh Agent' (the name of the sidebar panel)")
    if not str(config.get("panel_icon", "")).startswith("mdi:"):
        err("panel_icon must be an mdi: icon")
    for volume in config.get("map", []):
        if isinstance(volume, dict) and volume.get("type") not in ("data",) and volume.get("read_only") is not True:
            err(f"map {volume.get('type')}: must be mounted read-only")


# --------------------------------------------------------------------------- versions
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def check_versions(config: dict) -> None:
    version = config["version"]
    if not SEMVER.match(str(version)):
        err(f"version {version!r} is not MAJOR.MINOR.PATCH")

    changelog = (APP / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.MULTILINE)
    if not headings or headings[0] != version:
        err(f"CHANGELOG.md: the newest entry is {headings[0] if headings else 'missing'}, config.yaml says {version}")

    image = config.get("image", "")
    if not re.fullmatch(r"ghcr\.io/[a-z0-9-]+/" + re.escape(config["slug"]), image):
        err(f"image {image!r} must be ghcr.io/<lowercase owner>/{config['slug']}")

    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    from_line = re.search(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    if not from_line or not re.search(r"@sha256:[0-9a-f]{64}$", from_line.group(1)):
        err("Dockerfile: the base image must be pinned by digest")
    for stage in ("ui-web", "ui-server"):
        builder = re.search(rf"^FROM (\S+) AS {stage}$", dockerfile, re.MULTILINE)
        if not builder or not re.search(r"@sha256:[0-9a-f]{64}$", builder.group(1)):
            err(f"Dockerfile: the {stage} builder image must be pinned by digest")
    if 'ENTRYPOINT ["/usr/local/bin/wazuh-ha-entrypoint"]' not in dockerfile:
        err("Dockerfile: the entrypoint must be /usr/local/bin/wazuh-ha-entrypoint (the app supervises itself)")
    wazuh = re.search(r"^ARG WAZUH_VERSION=(\S+)", dockerfile, re.MULTILINE)
    if not wazuh or not SEMVER.match(wazuh.group(1)):
        err("Dockerfile: ARG WAZUH_VERSION must be a plain version such as 4.14.9")
    fingerprint = re.search(r"^ARG WAZUH_GPG_FINGERPRINT=([0-9A-F]{40})$", dockerfile, re.MULTILINE)
    if not fingerprint:
        err("Dockerfile: ARG WAZUH_GPG_FINGERPRINT must hold the 40 hex digit signing key fingerprint")
    plain = changelog.replace("*", "")
    if wazuh and f"Wazuh {wazuh.group(1)}" not in plain and f"Wazuh agent {wazuh.group(1)}" not in plain:
        err(f"CHANGELOG.md never mentions Wazuh agent {wazuh.group(1)}")


def check_files(config: dict) -> None:
    for name in ("README.md", "DOCS.md", "CHANGELOG.md", "icon.png", "logo.png", "apparmor.txt", "Dockerfile",
                 "ui/server/go.mod", "ui/web/package-lock.json", "rootfs/usr/local/bin/wazuh-ha-entrypoint",
                 "rootfs/usr/local/bin/wazuh-ha-host", "rootfs/usr/local/lib/wazuh-ha/hostns-start"):
        if not (APP / name).is_file():
            err(f"wazuh_agent/{name} is missing")
    repo = ROOT / "repository.yaml"
    if not repo.is_file():
        err("repository.yaml is missing")
    else:
        data = load_yaml(repo)
        for key in ("name", "url", "maintainer"):
            if not data.get(key):
                err(f"repository.yaml: {key} is missing")
    for arch in config["arch"]:
        if arch not in ("aarch64", "amd64"):
            err(f"arch {arch!r}: Home Assistant only supports aarch64 and amd64")


# --------------------------------------------------------------------------- the app's SCA policy
SCA_POLICY = APP / "rootfs" / "usr" / "local" / "lib" / "wazuh-ha" / "sca" / "home_assistant_os.yml"
# Wazuh's own policies use 1000 to 41065 (4.14.9), and an ID must be unique across policy files.
SCA_CHECK_IDS = range(910000, 911000)
SCA_CONDITIONS = {"all", "any", "none"}
SCA_COMPARE = re.compile(r" compare (<=|>=|==|!=|<|>) -?\d+$")


def check_sca_rule(where: str, rule, regex_type: str) -> None:
    """One rule, in the syntax of wm_sca.c: [not ]f:|d:|p:|c:TARGET[ -> MINTERM[ && MINTERM]...]."""
    if not isinstance(rule, str):
        err(f"{where}: a rule must be a string")
        return
    text = rule[4:] if rule.startswith("not ") else rule
    if not text.startswith(("f:", "d:", "p:", "c:")):
        err(f"{where}: {rule!r} does not start with f:, d:, p: or c: (after an optional 'not ')")
        return
    target, arrow, content = text.partition(" -> ")
    if not target[2:].strip():
        err(f"{where}: {rule!r} has no target")
    if "->" in target:
        err(f"{where}: {rule!r}: the arrow needs a space on both sides")
    if text.startswith("c:") and not arrow:
        err(f"{where}: {rule!r}: a command rule needs a pattern for its output (without one it only says the command ran)")
    if text.startswith("p:") and arrow:
        err(f"{where}: {rule!r}: a process rule only checks that the process exists")
    if not arrow:
        return
    for minterm in content.split(" && "):
        minterm = minterm[1:] if minterm.startswith("!") else minterm
        if minterm.startswith(("r:", "n:")):
            pattern = minterm[2:]
            if minterm.startswith("n:"):
                if not SCA_COMPARE.search(pattern):
                    err(f"{where}: {rule!r}: n: needs ' compare OPERATOR NUMBER' at the end")
                    continue
                pattern = SCA_COMPARE.sub("", pattern)
                if "(" not in pattern:
                    err(f"{where}: {rule!r}: n: needs a capture group for the number")
            try:
                re.compile(pattern)
            except re.error as problem:
                err(f"{where}: {rule!r}: the regular expression is not valid: {problem}")
            if regex_type != "pcre2" and re.search(r"\[|\{|\?", pattern):
                err(f"{where}: {rule!r}: Wazuh's own regular expressions have no classes, {{}} or ? (use regex_type: pcre2)")
        elif not minterm:
            err(f"{where}: {rule!r}: an empty pattern")


def check_sca_policy() -> None:
    if not SCA_POLICY.is_file():
        err(f"{SCA_POLICY.relative_to(ROOT)} is missing")
        return
    document = load_yaml(SCA_POLICY)
    for section in ("policy", "requirements", "checks"):
        if section not in document:
            err(f"sca policy: the section {section} is missing")
            return
    policy = document["policy"]
    for key in ("id", "file", "name", "description"):
        if not str(policy.get(key, "")).strip():
            err(f"sca policy: policy.{key} is required")
    if policy.get("file") != SCA_POLICY.name:
        err(f"sca policy: policy.file must be {SCA_POLICY.name!r}")
    regex_type = policy.get("regex_type", "osregex")
    if regex_type not in ("pcre2", "osregex"):
        err(f"sca policy: regex_type {regex_type!r} is neither pcre2 nor osregex")
    requirements = document["requirements"]
    for key in ("title", "description", "condition", "rules"):
        if not requirements.get(key):
            err(f"sca policy: requirements.{key} is required")
    if requirements.get("condition") not in SCA_CONDITIONS:
        err(f"sca policy: requirements.condition must be one of {sorted(SCA_CONDITIONS)}")
    for index, rule in enumerate(requirements.get("rules") or []):
        check_sca_rule(f"sca policy requirements.rules[{index}]", rule, regex_type)

    seen: set[int] = set()
    for index, check in enumerate(document["checks"]):
        where = f"sca policy check #{index + 1}"
        check_id = check.get("id")
        if not isinstance(check_id, int) or isinstance(check_id, bool):
            err(f"{where}: id must be an integer")
            continue
        where = f"sca policy check {check_id}"
        if check_id not in SCA_CHECK_IDS:
            err(f"{where}: id must be in {SCA_CHECK_IDS.start} to {SCA_CHECK_IDS.stop - 1} (this app's range)")
        if check_id in seen:
            err(f"{where}: id used twice")
        seen.add(check_id)
        for key in ("title", "description", "rationale", "remediation"):
            if not str(check.get(key, "")).strip():
                err(f"{where}: {key} is required (the dashboard shows it)")
        if check.get("condition") not in SCA_CONDITIONS:
            err(f"{where}: condition must be one of {sorted(SCA_CONDITIONS)}")
        rules = check.get("rules")
        if not isinstance(rules, list) or not rules:
            err(f"{where}: rules must be a list with at least one rule")
            continue
        for rule_index, rule in enumerate(rules):
            check_sca_rule(f"{where} rules[{rule_index}]", rule, regex_type)
    if not seen:
        err("sca policy: no checks")

    # The path the configuration names and the file the renderer copies are this one policy.
    context = (APP / "rootfs/usr/local/lib/wazuh-ha/ctx.jq").read_text(encoding="utf-8")
    renderer = (APP / "rootfs/usr/local/bin/wazuh-ha-render").read_text(encoding="utf-8")
    if f"ruleset/ha/{SCA_POLICY.name}" not in context:
        err(f"ctx.jq does not name ruleset/ha/{SCA_POLICY.name}")
    if f"sca/{SCA_POLICY.name}" not in renderer:
        err(f"wazuh-ha-render does not copy sca/{SCA_POLICY.name}")


def main() -> int:
    config = load_yaml(APP / "config.yaml")
    translations = load_yaml(APP / "translations" / "en.yaml")
    check_options(config, translations)
    check_security(config)
    check_files(config)
    check_sca_policy()
    if (APP / "CHANGELOG.md").is_file() and (APP / "Dockerfile").is_file():
        check_versions(config)

    rating = security_rating(config, (APP / "apparmor.txt").is_file())
    if errors:
        print(f"{len(errors)} problem(s):")
        for message in errors:
            print(f"  - {message}")
        return 1
    print(f"config OK: {len(config['schema'])} options, security rating {rating}/8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
