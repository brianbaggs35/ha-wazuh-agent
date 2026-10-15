#!/usr/bin/env python3
"""Keep the app on the newest stable Wazuh agent.

    scripts/wazuh_update.py check              # print what is current and what is newest
    scripts/wazuh_update.py apply              # update the Dockerfile, config.yaml and CHANGELOG

The newest agent is read from Wazuh's official apt repository index (the same repository
the Dockerfile installs from), so "newest" always means "installable".

`apply` changes three things together, because they must never disagree:
  * wazuh_agent/Dockerfile        ARG WAZUH_VERSION / WAZUH_PKG_REVISION
  * wazuh_agent/config.yaml       the app version (minor bump when Wazuh's minor version
                                  changes, patch bump otherwise)
  * wazuh_agent/CHANGELOG.md      a new "unreleased" entry

It refuses to proceed if the Wazuh package signing key is no longer the one pinned in the
Dockerfile: that is a event for a human to look at, never to auto-accept.

Exit status: 0 on success (including "nothing to do"), 1 on error.
Output: one JSON object on stdout, for the workflow to read.
"""

from __future__ import annotations

import argparse
import gzip
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "wazuh_agent"

INDEX_URL = "https://packages.wazuh.com/4.x/apt/dists/stable/main/binary-amd64/Packages.gz"
KEY_URL = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)-(\d+)$")


class UpdateError(Exception):
    """Something a human needs to look at."""


# ----------------------------------------------------------------------------- reading
def parse_packages(text: str) -> list[tuple[tuple[int, int, int], int]]:
    """Return (version, revision) for every wazuh-agent stanza in an apt Packages index."""
    found = []
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            # Continuation lines (leading space) and anything that is not "Key: value" are skipped.
            if ": " in line and not line.startswith(" "):
                key, value = line.split(": ", 1)
                fields[key] = value
        if fields.get("Package") != "wazuh-agent":
            continue
        match = VERSION_RE.match(fields.get("Version", ""))
        if match:
            major, minor, patch, revision = (int(part) for part in match.groups())
            found.append(((major, minor, patch), revision))
    return found


def newest(entries: list[tuple[tuple[int, int, int], int]]) -> tuple[tuple[int, int, int], int]:
    if not entries:
        raise UpdateError("no wazuh-agent versions found in the repository index")
    return max(entries)


def fmt(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def parse_version(text: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        raise UpdateError(f"not a plain version: {text!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ha-wazuh-agent-update-check"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 (fixed https URLs)
        return response.read()


def key_fingerprint(key_bytes: bytes) -> str:
    result = subprocess.run(
        ["gpg", "--show-keys", "--with-colons"],
        input=key_bytes,
        capture_output=True,
        check=True,
    )
    for line in result.stdout.decode().splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise UpdateError("no fingerprint found in the Wazuh signing key")


# ----------------------------------------------------------------------------- editing
def bump_app_version(app_version: str, old_wazuh: tuple[int, int, int], new_wazuh: tuple[int, int, int]) -> str:
    major, minor, patch = parse_version(app_version)
    if old_wazuh[:2] != new_wazuh[:2]:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def read_dockerfile_version(text: str) -> tuple[tuple[int, int, int], int]:
    version = re.search(r"^ARG WAZUH_VERSION=(\S+)$", text, re.MULTILINE)
    revision = re.search(r"^ARG WAZUH_PKG_REVISION=(\d+)$", text, re.MULTILINE)
    if not version or not revision:
        raise UpdateError("Dockerfile: ARG WAZUH_VERSION / ARG WAZUH_PKG_REVISION not found")
    return parse_version(version.group(1)), int(revision.group(1))


def update_dockerfile(text: str, version: tuple[int, int, int], revision: int) -> str:
    text = re.sub(r"^ARG WAZUH_VERSION=\S+$", f"ARG WAZUH_VERSION={fmt(version)}", text, flags=re.MULTILINE)
    return re.sub(r"^ARG WAZUH_PKG_REVISION=\d+$", f"ARG WAZUH_PKG_REVISION={revision}", text, flags=re.MULTILINE)


def update_config(text: str, app_version: str) -> str:
    updated, count = re.subn(r'^version: "[^"]*"$', f'version: "{app_version}"', text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise UpdateError('config.yaml: the line version: "..." was not found')
    return updated


def update_changelog(text: str, app_version: str, old_wazuh: tuple[int, int, int], new_wazuh: tuple[int, int, int]) -> str:
    entry = (
        f"## [{app_version}] - unreleased\n"
        f"\n"
        f"Wazuh agent **{fmt(new_wazuh)}**.\n"
        f"\n"
        f"### Changed\n"
        f"\n"
        f"- Updated the Wazuh agent from {fmt(old_wazuh)} to {fmt(new_wazuh)}. Make sure your Wazuh manager\n"
        f"  is not older than the agent before updating the app (see \"Updating\" in the documentation).\n"
        f"\n"
    )
    match = re.search(r"^## \[", text, re.MULTILINE)
    if not match:
        raise UpdateError("CHANGELOG.md: no existing entry to insert before")
    return text[: match.start()] + entry + text[match.start():]


# ----------------------------------------------------------------------------- commands
def current_state() -> dict:
    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    version, revision = read_dockerfile_version(dockerfile)
    config = (APP / "config.yaml").read_text(encoding="utf-8")
    app = re.search(r'^version: "([^"]*)"$', config, re.MULTILINE)
    if not app:
        raise UpdateError('config.yaml: the line version: "..." was not found')
    return {
        "current": fmt(version),
        "current_revision": revision,
        "app_version": app.group(1),
    }


def load_index() -> str:
    return gzip.decompress(fetch(INDEX_URL)).decode("utf-8")


def check(index_text: str) -> dict:
    state = current_state()
    latest_version, latest_revision = newest(parse_packages(index_text))
    state.update(
        latest=fmt(latest_version),
        latest_revision=latest_revision,
        update_available=(latest_version, latest_revision)
        > (parse_version(state["current"]), state["current_revision"]),
    )
    return state


def apply(index_text: str, verify_key: bool = True) -> dict:
    state = check(index_text)
    if not state["update_available"]:
        state["changed"] = False
        return state

    dockerfile_path = APP / "Dockerfile"
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    pinned = re.search(r"^ARG WAZUH_GPG_FINGERPRINT=([0-9A-F]{40})$", dockerfile, re.MULTILINE)
    if not pinned:
        raise UpdateError("Dockerfile: ARG WAZUH_GPG_FINGERPRINT not found")
    if verify_key:
        live = key_fingerprint(fetch(KEY_URL))
        if live != pinned.group(1):
            raise UpdateError(
                f"the Wazuh package signing key changed (pinned {pinned.group(1)}, repository serves {live}). "
                "Not updating automatically: verify the change with Wazuh before accepting the new key."
            )

    old = parse_version(state["current"])
    new = parse_version(state["latest"])
    app_version = bump_app_version(state["app_version"], old, new)

    dockerfile_path.write_text(update_dockerfile(dockerfile, new, state["latest_revision"]), encoding="utf-8")
    config_path = APP / "config.yaml"
    config_path.write_text(update_config(config_path.read_text(encoding="utf-8"), app_version), encoding="utf-8")
    changelog_path = APP / "CHANGELOG.md"
    changelog_path.write_text(
        update_changelog(changelog_path.read_text(encoding="utf-8"), app_version, old, new), encoding="utf-8"
    )

    state.update(changed=True, new_app_version=app_version, minor_change=old[:2] != new[:2])
    return state


def main(argv: list[str] | None = None) -> int:
    # Deliberately no option that names a file or skips the key check: the only input is the
    # repository index fetched over HTTPS, and the only files touched are the three in wazuh_agent/.
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("check", "apply"))
    args = parser.parse_args(argv)
    try:
        index_text = load_index()
        result = check(index_text) if args.command == "check" else apply(index_text)
    except (UpdateError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
