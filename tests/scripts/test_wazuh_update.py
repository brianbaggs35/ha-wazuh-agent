"""Tests for scripts/wazuh_update.py. No network: every outside call is replaced."""

import contextlib
import gzip
import importlib.util
import io
import json
import pathlib
import runpy
import subprocess
import tempfile
import unittest
import urllib.error
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "wazuh_update.py"
SPEC = importlib.util.spec_from_file_location("wazuh_update", SCRIPT)
wazuh_update = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wazuh_update)

FINGERPRINT = "A" * 40

INDEX = """Package: wazuh-manager
Version: 4.99.0-1

Package: wazuh-agent
Version: 4.14.9-1
Description: Wazuh agent
 a continuation line, which is not a field
a line that is not a field either
Filename: pool/main/w/wazuh-agent/wazuh-agent_4.14.9-1_amd64.deb

Package: wazuh-agent
Version: 4.14.10-1

Package: wazuh-agent
Version: 4.9.2-1

Package: wazuh-agent
Version: not-a-version

Package: wazuh-agent
Version: 4.14.10-2
"""

DOCKERFILE = (
    "FROM x\n"
    "ARG WAZUH_VERSION=4.14.9\n"
    "ARG WAZUH_PKG_REVISION=1\n"
    f"ARG WAZUH_GPG_FINGERPRINT={FINGERPRINT}\n"
)
CONFIG = 'name: x\nversion: "1.0.0"\nimage: y\n'
CHANGELOG = "# Changelog\n\nintro\n\n## [1.0.0] - 2026-10-15\n\nold\n"


class ParsingTests(unittest.TestCase):
    def test_only_agent_stanzas_with_real_versions_count(self):
        found = wazuh_update.parse_packages(INDEX)
        self.assertEqual(len(found), 4)
        self.assertNotIn(((4, 99, 0), 1), found)

    def test_newest_compares_numbers_not_text(self):
        # 4.14.10 must beat 4.14.9 and 4.9.2 (a text comparison gets this wrong)
        self.assertEqual(wazuh_update.newest(wazuh_update.parse_packages(INDEX)), ((4, 14, 10), 2))

    def test_no_agent_versions_is_an_error(self):
        entries = wazuh_update.parse_packages("Package: other\nVersion: 1.0.0-1\n")
        with self.assertRaises(wazuh_update.UpdateError):
            wazuh_update.newest(entries)

    def test_parse_version_rejects_anything_but_three_numbers(self):
        self.assertEqual(wazuh_update.parse_version("4.14.9"), (4, 14, 9))
        for bad in ("4.14", "4.14.9-1", "v4.14.9", ""):
            with self.subTest(bad=bad), self.assertRaises(wazuh_update.UpdateError):
                wazuh_update.parse_version(bad)


class NetworkTests(unittest.TestCase):
    def test_fetch_asks_for_the_url_with_a_timeout_and_returns_the_body(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"body"
        with mock.patch.object(wazuh_update.urllib.request, "urlopen", return_value=response) as urlopen:
            self.assertEqual(wazuh_update.fetch("https://example.invalid/x"), b"body")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.invalid/x")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 60)

    def test_load_index_unpacks_the_repository_index(self):
        with mock.patch.object(wazuh_update, "fetch", return_value=gzip.compress(INDEX.encode())) as fetch:
            self.assertEqual(wazuh_update.load_index(), INDEX)
        fetch.assert_called_once_with(wazuh_update.INDEX_URL)

    def test_key_fingerprint_is_the_first_fpr_record(self):
        gpg_output = b"pub:-:4096:1:ABCDEF:1:::-:::scESC::::::23::0:\n" + f"fpr:::::::::{FINGERPRINT}:\n".encode()
        completed = subprocess.CompletedProcess([], 0, stdout=gpg_output)
        with mock.patch.object(wazuh_update.subprocess, "run", return_value=completed) as run:
            self.assertEqual(wazuh_update.key_fingerprint(b"key"), FINGERPRINT)
        self.assertEqual(run.call_args.kwargs["input"], b"key")

    def test_key_without_a_fingerprint_is_an_error(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b"pub:-:4096:1:ABCDEF:1:::-:::scESC::::::23::0:\n")
        with mock.patch.object(wazuh_update.subprocess, "run", return_value=completed):
            with self.assertRaises(wazuh_update.UpdateError):
                wazuh_update.key_fingerprint(b"key")


class VersionBumpTests(unittest.TestCase):
    def test_patch_update_bumps_the_app_patch(self):
        self.assertEqual(wazuh_update.bump_app_version("1.2.3", (4, 14, 8), (4, 14, 9)), "1.2.4")

    def test_minor_update_bumps_the_app_minor_and_resets_patch(self):
        self.assertEqual(wazuh_update.bump_app_version("1.2.3", (4, 14, 9), (4, 15, 0)), "1.3.0")

    def test_major_update_is_also_a_minor_bump_of_the_app(self):
        self.assertEqual(wazuh_update.bump_app_version("1.2.3", (4, 14, 9), (5, 0, 0)), "1.3.0")


class EditingTests(unittest.TestCase):
    def test_dockerfile_update_touches_only_the_two_args(self):
        out = wazuh_update.update_dockerfile(DOCKERFILE, (4, 15, 0), 2)
        self.assertIn("ARG WAZUH_VERSION=4.15.0\n", out)
        self.assertIn("ARG WAZUH_PKG_REVISION=2\n", out)
        self.assertIn(f"ARG WAZUH_GPG_FINGERPRINT={FINGERPRINT}", out)
        self.assertEqual(wazuh_update.read_dockerfile_version(out), ((4, 15, 0), 2))

    def test_a_dockerfile_missing_either_arg_is_an_error(self):
        for text in ("ARG WAZUH_VERSION=4.14.9\n", "ARG WAZUH_PKG_REVISION=1\n", "FROM x\n"):
            with self.subTest(text=text), self.assertRaises(wazuh_update.UpdateError):
                wazuh_update.read_dockerfile_version(text)

    def test_config_update_changes_the_version_line_only(self):
        self.assertEqual(wazuh_update.update_config(CONFIG, "1.0.1"), 'name: x\nversion: "1.0.1"\nimage: y\n')

    def test_config_without_a_version_line_is_an_error(self):
        with self.assertRaises(wazuh_update.UpdateError):
            wazuh_update.update_config("name: x\n", "1.0.1")

    def test_changelog_entry_goes_above_the_previous_one(self):
        out = wazuh_update.update_changelog(CHANGELOG, "1.0.1", (4, 14, 9), (4, 14, 10))
        self.assertLess(out.index("## [1.0.1] - unreleased"), out.index("## [1.0.0]"))
        self.assertIn("Wazuh agent **4.14.10**", out)
        self.assertIn("from 4.14.9 to 4.14.10", out)
        self.assertTrue(out.startswith("# Changelog\n\nintro\n\n"))

    def test_a_changelog_without_any_entry_is_an_error(self):
        with self.assertRaises(wazuh_update.UpdateError):
            wazuh_update.update_changelog("# Changelog\n", "1.0.1", (4, 14, 9), (4, 14, 10))


class ScratchAppTestCase(unittest.TestCase):
    """Runs the commands against a scratch copy of the three files they edit."""

    dockerfile = DOCKERFILE
    config = CONFIG
    changelog = CHANGELOG

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = pathlib.Path(self.tmp.name)
        (self.app / "Dockerfile").write_text(self.dockerfile, encoding="utf-8")
        (self.app / "config.yaml").write_text(self.config, encoding="utf-8")
        (self.app / "CHANGELOG.md").write_text(self.changelog, encoding="utf-8")
        patcher = mock.patch.object(wazuh_update, "APP", self.app)
        patcher.start()
        self.addCleanup(patcher.stop)

    def read(self, name):
        return (self.app / name).read_text(encoding="utf-8")


class CurrentStateTests(ScratchAppTestCase):
    def test_reads_the_pinned_agent_and_the_app_version(self):
        self.assertEqual(
            wazuh_update.current_state(),
            {"current": "4.14.9", "current_revision": 1, "app_version": "1.0.0"},
        )

    def test_a_config_without_a_version_is_an_error(self):
        (self.app / "config.yaml").write_text("name: x\n", encoding="utf-8")
        with self.assertRaises(wazuh_update.UpdateError):
            wazuh_update.current_state()


class CheckTests(ScratchAppTestCase):
    def test_reports_an_update_without_changing_files(self):
        before = self.read("Dockerfile")
        result = wazuh_update.check(INDEX)
        self.assertTrue(result["update_available"])
        self.assertEqual(result["latest"], "4.14.10")
        self.assertEqual(self.read("Dockerfile"), before)

    def test_nothing_to_do_when_already_current(self):
        result = wazuh_update.check("Package: wazuh-agent\nVersion: 4.14.9-1\n")
        self.assertFalse(result["update_available"])

    def test_a_newer_package_revision_of_the_same_version_is_an_update(self):
        result = wazuh_update.check("Package: wazuh-agent\nVersion: 4.14.9-2\n")
        self.assertTrue(result["update_available"])


class ApplyTests(ScratchAppTestCase):
    def test_updates_all_three_files_consistently(self):
        result = wazuh_update.apply(INDEX, verify_key=False)
        self.assertTrue(result["changed"])
        self.assertFalse(result["minor_change"])
        self.assertEqual(result["new_app_version"], "1.0.1")
        self.assertIn("ARG WAZUH_VERSION=4.14.10", self.read("Dockerfile"))
        self.assertIn("ARG WAZUH_PKG_REVISION=2", self.read("Dockerfile"))
        self.assertIn('version: "1.0.1"', self.read("config.yaml"))
        self.assertIn("## [1.0.1] - unreleased", self.read("CHANGELOG.md"))

    def test_a_new_minor_version_bumps_the_app_minor(self):
        result = wazuh_update.apply("Package: wazuh-agent\nVersion: 4.15.0-1\n", verify_key=False)
        self.assertTrue(result["minor_change"])
        self.assertEqual(result["new_app_version"], "1.1.0")

    def test_is_idempotent(self):
        wazuh_update.apply(INDEX, verify_key=False)
        result = wazuh_update.apply(INDEX, verify_key=False)
        self.assertFalse(result["update_available"])
        self.assertFalse(result["changed"])

    def test_proceeds_when_the_signing_key_is_the_pinned_one(self):
        with mock.patch.object(wazuh_update, "fetch", return_value=b"key") as fetch, mock.patch.object(
            wazuh_update, "key_fingerprint", return_value=FINGERPRINT
        ) as fingerprint:
            result = wazuh_update.apply(INDEX)
        self.assertTrue(result["changed"])
        fetch.assert_called_once_with(wazuh_update.KEY_URL)
        fingerprint.assert_called_once_with(b"key")

    def test_refuses_when_the_signing_key_changed_and_edits_nothing(self):
        before = {name: self.read(name) for name in ("Dockerfile", "config.yaml", "CHANGELOG.md")}
        with mock.patch.object(wazuh_update, "fetch", return_value=b"key"), mock.patch.object(
            wazuh_update, "key_fingerprint", return_value="B" * 40
        ):
            with self.assertRaisesRegex(wazuh_update.UpdateError, "signing key changed"):
                wazuh_update.apply(INDEX)
        self.assertEqual({name: self.read(name) for name in before}, before)

    def test_refuses_without_a_pinned_fingerprint(self):
        (self.app / "Dockerfile").write_text("ARG WAZUH_VERSION=4.14.9\nARG WAZUH_PKG_REVISION=1\n", encoding="utf-8")
        with self.assertRaisesRegex(wazuh_update.UpdateError, "FINGERPRINT"):
            wazuh_update.apply(INDEX)


class CommandLineTests(ScratchAppTestCase):
    def run_main(self, *argv, load_index=INDEX):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(wazuh_update, "load_index", return_value=load_index), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(err):
            rc = wazuh_update.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_check_prints_json_and_changes_nothing(self):
        rc, out, _ = self.run_main("check")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["latest"], "4.14.10")
        self.assertIn("ARG WAZUH_VERSION=4.14.9", self.read("Dockerfile"))

    def test_apply_verifies_the_key_and_edits_the_files(self):
        with mock.patch.object(wazuh_update, "fetch", return_value=b"key"), mock.patch.object(
            wazuh_update, "key_fingerprint", return_value=FINGERPRINT
        ):
            rc, out, _ = self.run_main("apply")
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)["changed"])
        self.assertIn("ARG WAZUH_VERSION=4.14.10", self.read("Dockerfile"))

    def test_has_no_option_that_names_a_file_or_skips_the_key_check(self):
        for option in (["--index-file", "/etc/passwd"], ["--skip-key-check"]):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    wazuh_update.main(["check", *option])
                self.assertEqual(raised.exception.code, 2)

    def test_each_kind_of_failure_is_reported_and_exits_1(self):
        failures = (
            wazuh_update.UpdateError("a human needs to look"),
            urllib.error.URLError("offline"),
            subprocess.CalledProcessError(2, "gpg"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(wazuh_update, "load_index", side_effect=failure), contextlib.redirect_stdout(
                    out
                ), contextlib.redirect_stderr(err):
                    rc = wazuh_update.main(["check"])
                self.assertEqual(rc, 1)
                self.assertTrue(err.getvalue().startswith("error: "))
                self.assertEqual(out.getvalue(), "")

    def test_runs_as_a_script(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = gzip.compress(INDEX.encode())
        out = io.StringIO()
        with mock.patch("sys.argv", [str(SCRIPT), "check"]), mock.patch(
            "urllib.request.urlopen", return_value=response
        ), contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(json.loads(out.getvalue())["latest"], "4.14.10")


if __name__ == "__main__":
    unittest.main()
