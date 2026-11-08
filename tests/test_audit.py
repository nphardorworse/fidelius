#!/usr/bin/env python3
"""Tests for skills/audit/scripts/audit.py. Every secret here is fake and built at runtime."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "audit" / "scripts" / "audit.py"
sys.path.insert(0, str(SCRIPT.parent))

import audit  # noqa: E402

GH = "ghp" + "_" + "a1B2c3D4" * 5
AWS = "AKIA" + "ABCDEFGH12345678"
ANTHROPIC = "sk-" + "ant-" + "api03-" + "x9Y8z7W6" * 4
PW = "zq7-Plover-Harbor"


def jwt(role):
    body = base64.urlsafe_b64encode(json.dumps({"role": role}).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJIUzI1NiJ9.{body}.c2lnbmF0dXJlLXBhcnQ"


def kinds(text):
    return sorted(k for k, _, _ in audit.detect(text))


class Detect(unittest.TestCase):
    def assertFound(self, text, value):
        values = [v for _, v, _ in audit.detect(text)]
        self.assertIn(value, values, text)

    def test_passwords_inside_commands(self):
        for cmd in (
            f"Bash(PGPASSWORD={PW} psql -h db.example.com *)",
            f"Bash(MYSQL_PWD={PW} mysql -h db.example.com)",
            f"Bash(sshpass -p {PW} ssh root@203.0.113.9)",
            f"Bash(mysql -h db.example.com -uroot -p{PW} app)",
            f"Bash(tool --password {PW})",
            f"Bash(tool --password={PW})",
            f"Bash(tool --api-key {PW})",
            f'Bash(curl -H "Authorization: Bearer {PW}" https://api.example.com)',
            f'Bash(curl -H "X-Api-Key: {PW}" https://api.example.com)',
            f"Bash(curl -u admin:{PW} https://api.example.com)",
            f"Bash(psql postgres://app:{PW}@db.example.com/main)",
        ):
            self.assertFound(cmd, PW)

    def test_quoted_values_lose_their_quotes(self):
        self.assertFound(f"Bash(PGPASSWORD='{PW}' psql -h db.example.com)", PW)

    def test_provider_formats(self):
        self.assertEqual(kinds(f"Bash(gh auth login --with-token {GH})")[0], "GitHub token")
        self.assertIn("AWS access key", kinds(f"Bash(AWS_ACCESS_KEY_ID={AWS} aws s3 ls)"))
        self.assertIn("Anthropic API key", kinds(ANTHROPIC))

    def test_provider_match_is_not_counted_twice(self):
        self.assertEqual(kinds(f'Bash(curl -H "Authorization: Bearer {GH}" https://x.example.com)'), ["GitHub token"])

    def test_variables_and_placeholders_are_not_secrets(self):
        for cmd in (
            'Bash(PGPASSWORD="$DEMO_PW" psql -h db.example.com)',
            "Bash(PGPASSWORD=${DEMO_PW} psql -h db.example.com)",
            'Bash(curl -H "Authorization: Bearer $TOKEN" https://a.example.com)',
            "Bash(sshpass -p $PW ssh a@b)",
            "Bash(psql postgres://app:$PW@db.example.com/main)",
            "Bash(PGPASSWORD=<password> psql)",
            "Bash(PGPASSWORD=your-password-here psql)",
            "Bash(PGPASSWORD=* psql)",
            "Bash(npm run test *)",
            "Bash(mysql -p app)",
            "Bash(accio myapp *)",
            "Bash(echo PWD=/tmp/foo)",
        ):
            self.assertEqual(audit.detect(cmd), [], cmd)

    def test_local_hosts_are_low_confidence_and_public_hosts_high(self):
        self.assertEqual(audit.detect(f"PGPASSWORD={PW} psql -h localhost")[0][2], "low")
        self.assertEqual(audit.detect(f"psql postgres://a:{PW}@127.0.0.1/x")[0][2], "low")
        self.assertEqual(audit.detect(f"PGPASSWORD={PW} psql -h db.example.com")[0][2], "high")
        self.assertEqual(audit.detect(GH)[0][2], "high")

    def test_supabase_anon_key_is_public_and_service_role_is_not(self):
        self.assertEqual(audit.detect(jwt("anon")), [])
        self.assertEqual(kinds(jwt("service_role")), ["Supabase service-role key"])


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(os.path.realpath(self.tmp.name))
        self.xdg = self.home / "isolated-xdg"
        (self.xdg / "git").mkdir(parents=True)
        self.env = dict(
            os.environ,
            GIT_CONFIG_GLOBAL=os.devnull,
            XDG_CONFIG_HOME=str(self.xdg),
            GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
            GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, repo, *args):
        subprocess.run(["git", *args], cwd=repo, env=self.env, check=True, capture_output=True)

    def settings(self, root, allow, name="settings.local.json", **extra):
        path = Path(root) / ".claude" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"permissions": {"allow": allow}, **extra}))
        return path

    def repo(self, name):
        path = self.home / name
        path.mkdir(parents=True)
        self.git(path, "init", "-q", "-b", "main")
        (path / "a").write_text("a")
        self.git(path, "add", "a")
        self.git(path, "commit", "-qm", "init")
        return path

    def run_audit(self, *args):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.home), "--json", *args],
            env=self.env, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.output = result.stdout + result.stderr
        return json.loads(result.stdout)

    def secret(self, report):
        self.assertEqual(len(report["secrets"]), 1, report)
        return report["secrets"][0]

    def test_output_never_contains_a_value_or_part_of_one(self):
        repo = self.repo("leaky")
        self.settings(repo, [
            f"Bash(PGPASSWORD={PW} psql -h db.example.com *)",
            f'Bash(curl -H "Authorization: Bearer {GH}" https://x.example.com)',
            f"Bash(AWS_SECRET={AWS} aws s3 ls)",
        ], env={"STRIPE_API_KEY": ANTHROPIC})
        self.git(repo, "add", "-f", ".claude/settings.local.json")
        self.git(repo, "commit", "-qm", "oops")
        for args in ((), ("--text",)):
            result = subprocess.run([sys.executable, str(SCRIPT), str(self.home), *args],
                                    env=self.env, capture_output=True, text=True, timeout=120)
            out = result.stdout + result.stderr
            self.assertIn("settings.local.json", out)
            for value in (PW, GH, AWS, ANTHROPIC):
                self.assertNotIn(value, out)
                self.assertNotIn(value[:6], out)
                self.assertNotIn(value[-6:], out)

    def test_file_outside_any_repo(self):
        self.settings(self.home / "plain", [f"Bash(PGPASSWORD={PW} psql -h db.example.com)"])
        secret = self.secret(self.run_audit())
        self.assertEqual(secret["exposure"], "local")
        self.assertEqual(secret["locations"][0]["git"], "not a repo")
        self.assertEqual(secret["locations"][0]["where"], "permissions.allow[0]")

    def test_env_block_is_scanned_by_key_name(self):
        self.settings(self.home / "plain", [], env={"MY_SERVICE_TOKEN": PW, "PORT": "3000"})
        secret = self.secret(self.run_audit())
        self.assertEqual(secret["locations"][0]["where"], "env.MY_SERVICE_TOKEN")

    def test_ignored_only_by_this_machine_is_reported(self):
        repo = self.repo("laptop")
        (self.xdg / "git" / "ignore").write_text("**/.claude/settings.local.json\n")
        self.settings(repo, [f"Bash(PGPASSWORD={PW} psql -h db.example.com)"])
        self.assertEqual(self.secret(self.run_audit())["locations"][0]["git"], "ignored on this machine only")

    def test_ignored_by_the_repo_is_reported(self):
        repo = self.repo("good")
        (repo / ".gitignore").write_text(".claude/settings.local.json\n")
        self.settings(repo, [f"Bash(PGPASSWORD={PW} psql -h db.example.com)"])
        self.assertEqual(self.secret(self.run_audit())["locations"][0]["git"], "ignored by the repo")

    def test_info_exclude_only_protects_this_clone(self):
        repo = self.repo("info")
        (repo / ".git" / "info" / "exclude").write_text(".claude/settings.local.json\n")
        self.settings(repo, [f"Bash(PGPASSWORD={PW} psql -h db.example.com)"])
        self.assertEqual(self.secret(self.run_audit())["locations"][0]["git"], "ignored on this machine only")

    def test_committed_but_never_pushed(self):
        repo = self.repo("unpushed")
        self.settings(repo, [f"Bash(PGPASSWORD={PW} psql -h db.example.com)"])
        self.git(repo, "add", ".claude/settings.local.json")
        self.git(repo, "commit", "-qm", "oops")
        secret = self.secret(self.run_audit())
        self.assertEqual(secret["exposure"], "committed")
        self.assertEqual({loc["git"] for loc in secret["locations"] if loc["state"] == "current"}, {"tracked"})

    def test_deleted_file_is_found_in_pushed_history(self):
        remote = self.home / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], env=self.env, check=True)
        repo = self.repo("deleted")
        self.settings(repo, [f"Bash(PGPASSWORD={PW} psql -h db.example.com)"])
        self.git(repo, "add", ".claude/settings.local.json")
        self.git(repo, "commit", "-qm", "oops")
        self.git(repo, "remote", "add", "origin", str(remote))
        self.git(repo, "push", "-q", "-u", "origin", "main")
        self.git(repo, "rm", "-q", ".claude/settings.local.json")
        self.git(repo, "commit", "-qm", "remove")
        secret = self.secret(self.run_audit())
        self.assertEqual(secret["exposure"], "pushed")
        self.assertEqual({loc["state"] for loc in secret["locations"]}, {"history"})
        self.assertRegex(secret["locations"][0]["commit"], r"^[0-9a-f]{7,}$")

    def test_same_value_in_two_places_is_one_secret(self):
        self.settings(self.home / "one", [f"Bash(PGPASSWORD={PW} psql -h db.example.com)"])
        self.settings(self.home / "two", [f"Bash(sshpass -p {PW} ssh root@203.0.113.9)"])
        self.assertEqual(len(self.secret(self.run_audit())["locations"]), 2)

    def test_shared_settings_file_is_scanned(self):
        self.settings(self.home / "team", [GH], name="settings.json")
        self.assertEqual(self.secret(self.run_audit())["kind"], "GitHub token")

    def test_skipped_folders(self):
        self.settings(self.home / "node_modules" / "pkg", [GH])
        self.settings(self.home / "Library" / "App", [GH])
        self.assertEqual(self.run_audit()["secrets"], [])

    def test_broken_json_is_counted_and_nothing_crashes(self):
        path = self.settings(self.home / "bad", [])
        path.write_text('{"permissions": ' + PW)
        report = self.run_audit()
        self.assertEqual(report["scanned"]["unreadable"], 1)
        self.assertNotIn(PW, self.output)

    def test_symlinks_are_not_followed(self):
        real = self.settings(self.home / "elsewhere" / "hidden", [GH])
        link = self.home / "linked" / ".claude" / "settings.local.json"
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        self.assertEqual(len(self.secret(self.run_audit())["locations"]), 1)

    def test_repo_config_cannot_run_code(self):
        repo = self.repo("hostile")
        canary = self.home / "canary"
        hook = self.home / "evil.sh"
        hook.write_text(f"#!/bin/sh\ntouch {canary}\n")
        hook.chmod(0o755)
        self.git(repo, "config", "core.fsmonitor", str(hook))
        self.git(repo, "config", "core.sshCommand", str(hook))
        self.settings(repo, [GH])
        self.run_audit()
        self.assertFalse(canary.exists())

    def test_credentials_in_a_remote_url_are_never_printed(self):
        repo = self.repo("remote-cred")
        self.git(repo, "remote", "add", "origin", f"https://user:{PW}@github.example.com/o/r.git")
        self.settings(repo, [GH])
        self.run_audit()
        self.assertNotIn(PW, self.output)

    def test_clean_home_reports_nothing(self):
        self.settings(self.home / "ok", ["Bash(npm run test *)"])
        report = self.run_audit()
        self.assertEqual(report["secrets"], [])
        self.assertEqual(report["scanned"]["settings_files"], 1)


if __name__ == "__main__":
    unittest.main()
