import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import main


class TestManifestChecker(unittest.TestCase):
    def test_safe_manifest_has_no_issues(self):
        manifest = {
            "server": "demo",
            "allowed_tools": ["read_file", "list_files"],
            "tools": [{"name": "read_file"}],
            "paths": ["project/docs"],
            "network": False,
        }
        self.assertEqual(main.check_manifest(manifest), [])

    def test_string_tools_are_supported(self):
        manifest = {
            "server": "demo",
            "allowed_tools": ["read_file"],
            "tools": ["read_file"],
            "paths": [],
            "network": False,
        }
        self.assertEqual(main.check_manifest(manifest), [])

    def test_unsafe_entries_are_reported(self):
        manifest = {
            "server": "demo",
            "allowed_tools": ["read_file"],
            "tools": [{"name": "shell"}],
            "paths": ["../secrets"],
            "network": True,
        }
        issues = main.check_manifest(manifest)
        self.assertIn("tool not on allowlist: shell", issues)
        self.assertIn("unsafe tool requested: shell", issues)
        self.assertIn("unsafe path outside workspace: ../secrets", issues)
        self.assertIn("network access is enabled", issues)

    def test_require_allowlist_flags_declared_tools_without_allowlist(self):
        manifest = {"server": "demo", "tools": ["read_file"], "paths": []}
        issues = main.check_manifest(manifest, require_allowlist=True)
        self.assertIn("allowed_tools is required when tools are declared", issues)

    def test_unsupported_tool_entry_type_is_reported(self):
        manifest = {"server": "demo", "tools": [123], "paths": []}
        issues = main.check_manifest(manifest)
        self.assertIn("tool entry has unsupported type: int", issues)

    def test_cli_can_load_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps({"server": "demo"}), encoding="utf-8")
            manifest = main.load_manifest(path)
            self.assertEqual(manifest["server"], "demo")

    def test_cli_can_load_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.toml"
            path.write_text(
                '\ufeffserver = "demo"\nallowed_tools = ["read_file"]\nnetwork = false\n[[tools]]\nname = "read_file"\n',
                encoding="utf-8",
            )
            manifest = main.load_manifest(path)
            self.assertEqual(manifest["server"], "demo")
            self.assertEqual(manifest["tools"][0]["name"], "read_file")

    def test_cli_require_allowlist_returns_json_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text(json.dumps({"server": "demo", "tools": ["read_file"]}), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(main.__file__)),
                    "--manifest",
                    str(manifest_path),
                    "--json",
                    "--require-allowlist",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 1)
            payload = json.loads(completed.stdout)
            self.assertIn("allowed_tools is required when tools are declared", payload["issues"])

    def test_sarif_output_contains_rules_and_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text(
                json.dumps({"server": "demo", "tools": ["shell"], "allowed_tools": ["read_file"]}),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(main.__file__)),
                    "--manifest",
                    str(manifest_path),
                    "--format",
                    "sarif",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 1)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["version"], "2.1.0")
            rule_ids = {rule["id"] for rule in payload["runs"][0]["tool"]["driver"]["rules"]}
            self.assertIn("tool-not-on-allowlist", rule_ids)
            self.assertIn("unsafe-tool", rule_ids)
            self.assertEqual(payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


if __name__ == "__main__":
    unittest.main()
