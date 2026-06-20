import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PLUGIN = ROOT / "examples" / "anna-app-repoguardian-ai" / "executas" / "repoguardian-scanner"
if str(PLUGIN) not in sys.path:
    sys.path.insert(0, str(PLUGIN))

import repoguardian_scanner as scanner  # noqa: E402


class RepoGuardianScannerTests(unittest.TestCase):
    def test_local_scan_detects_secret_and_static_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"left-pad": "1.1.0"}}),
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "import subprocess\n"
                "import requests\n"
                "API_TOKEN = 'abcdefghijklmnopqrstuvwxyz1234567890TOKEN'\n"
                "subprocess.call('echo hello', shell=True)\n"
                "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
                "requests.get('https://example.com')\n",
                encoding="utf-8",
            )
            (root / "web.js").write_text(
                "const fs = require('fs');\n"
                "db.query(`SELECT * FROM users WHERE name = ${name}`);\n"
                "document.body.innerHTML = html;\n"
                "fs.readFileSync('large.json');\n",
                encoding="utf-8",
            )

            result = scanner.scan_repository(
                source_type="local_path",
                local_path=str(root),
                include_ai=False,
                dependency_network=False,
            )

        self.assertEqual(result["source"]["type"], "local_path")
        categories = {finding["category"] for finding in result["findings"]}
        self.assertIn("secret", categories)
        self.assertIn("static", categories)
        self.assertIn("injection", categories)
        self.assertIn("xss", categories)
        self.assertIn("architecture", categories)
        self.assertIn("performance", categories)
        self.assertGreaterEqual(result["summary"]["finding_count"], 6)
        rendered = json.dumps(result)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz1234567890TOKEN", rendered)

    def test_ai_request_without_host_sampling_uses_deterministic_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "API_TOKEN = 'abcdefghijklmnopqrstuvwxyz1234567890TOKEN'\n",
                encoding="utf-8",
            )

            result = scanner.scan_repository(
                source_type="local_path",
                local_path=str(root),
                include_ai=True,
                host_sampling=False,
                dependency_network=False,
            )

        self.assertEqual(result["risk_analysis"]["mode"], "deterministic")
        self.assertIn("host sampling is not granted", " ".join(result["warnings"]))

    def test_pr_dry_run_generates_report_files_without_token(self):
        scan_result = {
            "scan_id": "abc123",
            "created_at": "2026-06-20T00:00:00+00:00",
            "source": {"repository": "octo/demo", "repository_url": "https://github.com/octo/demo"},
            "inventory": {"manifests": ["package.json", "requirements.txt"]},
            "summary": {"risk_score": 42, "grade": "C", "finding_count": 1},
            "risk_analysis": {"executive_summary": "One high-risk issue."},
            "findings": [],
            "suggestions": [],
            "warnings": [],
        }

        result = scanner.create_pull_request(
            repository_url="https://github.com/octo/demo",
            scan_result=scan_result,
            dry_run=True,
        )

        self.assertTrue(result["dry_run"])
        paths = {item["path"] for item in result["files"]}
        self.assertIn(".github/repoguardian/security-report-abc123.md", paths)
        self.assertIn(".github/dependabot.yml", paths)
        self.assertIn(".gitignore", paths)

    def test_real_pr_requires_approval_and_token(self):
        with self.assertRaises(ValueError):
            scanner.create_pull_request(
                repository_url="octo/demo",
                scan_result={"scan_id": "abc123", "summary": {}, "risk_analysis": {}, "findings": []},
                dry_run=False,
                approved=False,
            )

    def test_patch_generation_requires_approval_and_returns_diff(self):
        scan_result = {
            "scan_id": "abc123",
            "created_at": "2026-06-20T00:00:00+00:00",
            "source": {"repository": "octo/demo"},
            "inventory": {"manifests": ["package.json"]},
            "summary": {"risk_score": 10, "grade": "B", "finding_count": 0},
            "risk_analysis": {"executive_summary": "Review findings."},
            "findings": [],
            "suggestions": [],
            "warnings": [],
        }
        with self.assertRaises(ValueError):
            scanner.generate_patch(scan_result=scan_result, approved=False)
        patch = scanner.generate_patch(scan_result=scan_result, approved=True)
        self.assertEqual(patch["filename"], "repoguardian-fixes-abc123.patch")
        self.assertIn("diff --git", patch["patch_text"])
        self.assertIn(".github/repoguardian/security-report-abc123.md", patch["patch_text"])

    def test_stdio_invoke_contract_returns_scan_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text(
                "import subprocess\n"
                "API_TOKEN = 'abcdefghijklmnopqrstuvwxyz1234567890TOKEN'\n"
                "subprocess.call('echo hello', shell=True)\n",
                encoding="utf-8",
            )
            proc = subprocess.Popen(
                [sys.executable, str(PLUGIN / "repoguardian_scanner.py")],
                cwd=str(ROOT / "examples" / "anna-app-repoguardian-ai"),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "invoke",
                "params": {
                    "tool": "scan_repository",
                    "arguments": {
                        "source_type": "local_path",
                        "local_path": str(root),
                        "include_ai": False,
                        "dependency_network": False,
                    },
                },
            }
            stdout, stderr = proc.communicate(json.dumps(request) + "\n", timeout=10)

        self.assertEqual(proc.returncode, 0, stderr)
        response = json.loads(stdout.splitlines()[0])
        self.assertNotIn("error", response)
        self.assertTrue(response["result"]["success"])
        result = response["result"]["data"]
        self.assertGreaterEqual(result["summary"]["finding_count"], 2)
        self.assertIn("report_markdown", result)


if __name__ == "__main__":
    unittest.main()
