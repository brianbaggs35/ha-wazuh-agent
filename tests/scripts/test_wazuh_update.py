"""Tests for scripts/wazuh_update.py (no network)."""

import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("wazuh_update", ROOT / "scripts" / "wazuh_update.py")
wazuh_update = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wazuh_update)

INDEX = """Package: wazuh-manager
Version: 4.99.0-1

Package: wazuh-agent
Version: 4.14.9-1
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


class ParsingTests(unittest.TestCase):
    def test_only_agent_stanzas_with_real_versions_count(self):
        found = wazuh_update.parse_packages(INDEX)
        self.assertEqual(len(found), 4)
        self.assertNotIn(((4, 99, 0), 1), found)

    def test_newest_compares_numbers_not_text(self):
        # 4.14.10 must beat 4.14.9 and 4.9.2 (a text comparison gets this wrong)
        self.assertEqual(wazuh_update.newest(wazuh_update.parse_packages(INDEX)), ((4, 14, 10), 2))

    def test_empty_index_is_an_error(self):
        with self.assertRaises(wazuh_update.UpdateError):
            wazuh_update.newest(wazuh_update.parse_packages("Package: other\nVersion: 1.0.0-1\n"))


class VersionBumpTests(unittest.TestCase):
    def test_patch_update_bumps_the_app_patch(self):
        self.assertEqual(wazuh_update.bump_app_version("1.2.3", (4, 14, 8), (4, 14, 9)), "1.2.4")

    def test_minor_update_bumps_the_app_minor_and_resets_patch(self):
        self.assertEqual(wazuh_update.bump_app_version("1.2.3", (4, 14, 9), (4, 15, 0)), "1.3.0")

    def test_major_update_is_also_a_minor_bump_of_the_app(self):
        self.assertEqual(wazuh_update.bump_app_version("1.2.3", (4, 14, 9), (5, 0, 0)), "1.3.0")


class EditingTests(unittest.TestCase):
    DOCKERFILE = "FROM x\nARG WAZUH_VERSION=4.14.9\nARG WAZUH_PKG_REVISION=1\nARG WAZUH_GPG_FINGERPRINT=" + "A" * 40 + "\n"

    def test_dockerfile_update_touches_only_the_two_args(self):
        out = wazuh_update.update_dockerfile(self.DOCKERFILE, (4, 15, 0), 2)
        self.assertIn("ARG WAZUH_VERSION=4.15.0\n", out)
        self.assertIn("ARG WAZUH_PKG_REVISION=2\n", out)
        self.assertIn("ARG WAZUH_GPG_FINGERPRINT=" + "A" * 40, out)
        self.assertEqual(wazuh_update.read_dockerfile_version(out), ((4, 15, 0), 2))

    def test_config_update_changes_the_version_line_only(self):
        text = 'name: x\nversion: "1.0.0"\nimage: y\n'
        self.assertEqual(wazuh_update.update_config(text, "1.0.1"), 'name: x\nversion: "1.0.1"\nimage: y\n')

    def test_config_without_a_version_line_is_an_error(self):
        with self.assertRaises(wazuh_update.UpdateError):
            wazuh_update.update_config("name: x\n", "1.0.1")

    def test_changelog_entry_goes_above_the_previous_one(self):
        text = "# Changelog\n\nintro\n\n## [1.0.0] - 2026-10-15\n\nold\n"
        out = wazuh_update.update_changelog(text, "1.0.1", (4, 14, 9), (4, 14, 10))
        self.assertLess(out.index("## [1.0.1] - unreleased"), out.index("## [1.0.0]"))
        self.assertIn("Wazuh agent **4.14.10**", out)
        self.assertIn("from 4.14.9 to 4.14.10", out)
        self.assertTrue(out.startswith("# Changelog\n\nintro\n\n"))


class ApplyEndToEndTests(unittest.TestCase):
    """Runs the real command against a scratch copy of the app files."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        (self.tmp / "wazuh_agent").mkdir()
        for name in ("Dockerfile", "config.yaml", "CHANGELOG.md"):
            shutil.copy(ROOT / "wazuh_agent" / name, self.tmp / "wazuh_agent" / name)
        self.index = self.tmp / "Packages"
        self.index.write_text(INDEX, encoding="utf-8")
        self.original_app = wazuh_update.APP
        wazuh_update.APP = self.tmp / "wazuh_agent"

    def tearDown(self):
        wazuh_update.APP = self.original_app
        shutil.rmtree(self.tmp)

    def run_cli(self, command):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = wazuh_update.main([command, "--index-file", str(self.index), "--skip-key-check"])
        return rc, json.loads(out.getvalue()) if out.getvalue() else None

    def test_check_reports_an_update_without_changing_files(self):
        before = (wazuh_update.APP / "Dockerfile").read_text(encoding="utf-8")
        rc, result = self.run_cli("check")
        self.assertEqual(rc, 0)
        self.assertTrue(result["update_available"])
        self.assertEqual(result["latest"], "4.14.10")
        self.assertEqual((wazuh_update.APP / "Dockerfile").read_text(encoding="utf-8"), before)

    def test_apply_updates_all_three_files_consistently(self):
        rc, result = self.run_cli("apply")
        self.assertEqual(rc, 0)
        self.assertTrue(result["changed"])
        dockerfile = (wazuh_update.APP / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("ARG WAZUH_VERSION=4.14.10", dockerfile)
        self.assertIn("ARG WAZUH_PKG_REVISION=2", dockerfile)
        config = (wazuh_update.APP / "config.yaml").read_text(encoding="utf-8")
        self.assertIn(f'version: "{result["new_app_version"]}"', config)
        changelog = (wazuh_update.APP / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## [{result['new_app_version']}] - unreleased", changelog)

    def test_apply_is_idempotent(self):
        self.run_cli("apply")
        rc, result = self.run_cli("apply")
        self.assertEqual(rc, 0)
        self.assertFalse(result["update_available"])
        self.assertFalse(result["changed"])

    def test_nothing_to_do_when_already_current(self):
        self.index.write_text("Package: wazuh-agent\nVersion: 4.14.9-1\n", encoding="utf-8")
        rc, result = self.run_cli("check")
        self.assertEqual(rc, 0)
        self.assertFalse(result["update_available"])


if __name__ == "__main__":
    unittest.main()
