import json
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


if __name__ == "__main__":
    unittest.main()
