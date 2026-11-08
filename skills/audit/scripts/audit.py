#!/usr/bin/env python3
"""Find secrets saved in Claude Code settings files and their git history.

The report names the file, the rule and how far the secret has travelled. It never contains a
value, or any part or hash of one, so an agent can run this without the secrets reaching its
conversation. Standard library only, no network unless --github is passed.
"""
import argparse
import base64
import json
import os
import re
import shutil
import stat
import subprocess
import sys

SETTINGS_NAMES = ("settings.local.json", "settings.json")
SKIP_DIRS = {"node_modules", ".Trash", ".cache", ".npm", ".venv", "venv", "__pycache__", "DerivedData", "Pods", "build.noindex"}
MAX_FILE_BYTES = 5_000_000
MAX_COMMITS = 2000
HISTORY_PATHS = (":(glob)**/.claude/settings.json", ":(glob)**/.claude/settings.local.json")

PROVIDERS = [
    ("Anthropic API key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI API key", r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"),
    ("GitLab token", r"glpat-[A-Za-z0-9_-]{16,}"),
    ("npm token", r"npm_[A-Za-z0-9]{30,}"),
    ("AWS access key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("Slack token", r"xox[abeoprs]-[A-Za-z0-9-]{10,}"),
    ("Stripe live key", r"[sr]k_live_[A-Za-z0-9]{16,}"),
    ("Supabase account token", r"sbp_[a-f0-9]{30,}"),
    ("Google API key", r"AIza[A-Za-z0-9_-]{35}"),
    ("Hugging Face token", r"hf_[A-Za-z0-9]{30,}"),
    ("Private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+")

VALUE = r"""(?P<v>"[^"]*"|'[^']*'|[^\s;&|)'"]+)"""
SECRET_NAME = r"[A-Z0-9_]*(?:PASSWORD|PASSWD|_PWD|PASS|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*"
COMMAND_SHAPES = [
    ("Password in a command", r"(?:^|[\s(;&|])" + SECRET_NAME + "=" + VALUE),
    ("Password in a command", r"\bsshpass\s+-p\s*" + VALUE),
    ("Password in a command", r"\bmysql(?:dump|admin)?\b[^|;&]*?\s-p(?P<v>[^\s;&|)'\"]+)"),
    ("Password in a command", r"\s--(?:password|passwd|pass|token|api-?key|secret|auth-token|access-token|client-secret)[= ]\s*" + VALUE),
    ("Password in a command", r"\s(?:-u|--user)\s+['\"]?[^\s:'\"]+:(?P<v>[^\s'\")]+)"),
    ("Token in a request header", r"(?i)authorization:\s*(?:bearer|token|basic)\s+(?P<v>[^\s'\")]+)"),
    ("Token in a request header", r"(?i)(?:x-api-key|x-auth-token|api-key|apikey):\s*(?P<v>[^\s'\")]+)"),
    ("Password in a connection URL", r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@'\"]+:(?P<v>[^@/\s'\"]+)@"),
]
COMPILED_PROVIDERS = [(kind, re.compile(rx)) for kind, rx in PROVIDERS]
COMPILED_SHAPES = [(kind, re.compile(rx)) for kind, rx in COMMAND_SHAPES]
ENV_NAME = re.compile("^" + SECRET_NAME + "$", re.I)
LOCAL_HOST = re.compile(r"\b(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|host\.docker\.internal|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)\b|\[::1\]", re.I)
ANY_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)
PLACEHOLDER = re.compile(r"^(?:your[-_]|my[-_]|example|changeme|change[-_]me|placeholder|redacted|xxx+|\*+$|password$|secret$|token$|test$|true$|false$)", re.I)

EXPOSURE_RANK = {"pushed": 0, "committed": 1, "local": 2}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
LIMITS = [
    "Only this Mac and its local clones were checked. Forks and other people's clones are out of reach.",
    "Whether a commit was pushed comes from this clone's remote branches as of its last fetch.",
    "A clean result doesn't prove a key never leaked. Passwords in unusual shapes can be missed.",
    "Agent transcripts, memory files and .env files were not scanned.",
    "No key was tested. A finding means it looks like a secret, not that it still works.",
]


def is_placeholder(value):
    return len(value) < 4 or any(c in value for c in "$<>*") or "{{" in value or bool(PLACEHOLDER.match(value))


def confidence(text, value):
    rest = text.replace(value, " ")
    if LOCAL_HOST.search(rest):
        return "low"
    return "high" if ANY_HOST.search(rest) else "medium"


def jwt_kind(body):
    try:
        role = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))).get("role")
    except (ValueError, AttributeError):
        return "JSON web token"
    if role == "anon":
        return None  # Public by design.
    return "Supabase service-role key" if role == "service_role" else "JSON web token"


def detect(text):
    """Return (kind, value, confidence) for each secret in one string. Values stay in this process."""
    found = {}
    for kind, pattern in COMPILED_PROVIDERS:
        for match in pattern.finditer(text):
            found[match.group(0)] = (kind, "high")
    for match in JWT.finditer(text):
        kind = jwt_kind(match.group(1))
        if kind:
            found[match.group(0)] = (kind, "high" if kind.startswith("Supabase") else "medium")
    for kind, pattern in COMPILED_SHAPES:
        for match in pattern.finditer(text):
            value = match.group("v").strip("\"'")
            if is_placeholder(value) or any(value in known or known in value for known in found):
                continue
            found[value] = (kind, confidence(text, value))
    return [(kind, value, conf) for value, (kind, conf) in found.items()]


def walk_strings(node, path=""):
    if isinstance(node, dict):
        for key, child in node.items():
            if key != "$schema":
                yield from walk_strings(child, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from walk_strings(child, f"{path}[{index}]")
    elif isinstance(node, str):
        yield path, node


def scan_document(document):
    """Return (where, kind, value, confidence) for every secret in a parsed settings file."""
    results = []
    for where, text in walk_strings(document):
        hits = detect(text)
        parts = where.split(".")
        if not hits and len(parts) >= 2 and parts[-2] == "env" and ENV_NAME.match(parts[-1]) and not is_placeholder(text):
            hits = [("Secret in an env setting", text, "medium")]
        results.extend((where, kind, value, conf) for kind, value, conf in hits)
    return results


def git(repo, *args, timeout=60):
    """Run git without anything the repository's own config could execute."""
    command = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repo, *args]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    try:
        done = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return 1, b""
    return done.returncode, done.stdout


def discover(root):
    """Return (settings files, git repos, unreadable folder count) under root, without following links."""
    settings, repos, errors = [], [], []
    for dirpath, dirnames, filenames in os.walk(root, onerror=errors.append, followlinks=False):
        if dirpath == root and "Library" in dirnames:
            dirnames.remove("Library")
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if ".git" in dirnames or ".git" in filenames:
            repos.append(dirpath)
            if ".git" in dirnames:
                dirnames.remove(".git")
        if ".claude" in dirnames:
            dirnames.remove(".claude")
            for name in SETTINGS_NAMES:
                path = os.path.join(dirpath, ".claude", name)
                try:
                    if stat.S_ISREG(os.lstat(path).st_mode):
                        settings.append(path)
                except OSError:
                    pass
    return settings, repos, len(errors)


def parse(raw):
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, (dict, list)) else None


def read_settings(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as handle:
            return parse(handle.read())
    except OSError:
        return None


def git_state(path):
    """Describe how git treats a settings file on this machine."""
    folder = os.path.dirname(path)
    code, out = git(folder, "rev-parse", "--show-toplevel")
    if code != 0:
        return None, "not a repo"
    repo = out.decode("utf-8", "replace").strip()
    if git(folder, "ls-files", "--error-unmatch", path)[0] == 0:
        return repo, "tracked"
    code, out = git(folder, "check-ignore", "-v", path)
    if code != 0:
        return repo, "not ignored"
    source = out.decode("utf-8", "replace").split(":", 1)[0]
    in_repo = os.path.basename(source) == ".gitignore" and not source.startswith((".git/", "~")) and not os.path.isabs(source)
    return repo, "ignored by the repo" if in_repo else "ignored on this machine only"


def is_pushed(repo, commit, cache):
    if (repo, commit) not in cache:
        _, out = git(repo, "for-each-ref", "--count=1", f"--contains={commit}", "refs/remotes")
        cache[(repo, commit)] = bool(out.strip())
    return cache[(repo, commit)]


def history_versions(repo):
    """Yield (commit, path, parsed document) for each committed version of a settings file."""
    code, out = git(repo, "log", "--all", "--format=%H", "--name-only", "--diff-filter=AM", f"--max-count={MAX_COMMITS}", "--", *HISTORY_PATHS, timeout=120)
    if code != 0:
        return
    commit = None
    for line in out.decode("utf-8", "replace").splitlines():
        if re.fullmatch(r"[0-9a-f]{40,64}", line):
            commit = line
        elif line and commit:
            code, blob = git(repo, "cat-file", "blob", f"{commit}:{line}")
            document = parse(blob) if code == 0 else None
            if document is not None:
                yield commit, line, document


def github_visibility(repo):
    """Ask GitHub, through the user's own gh login, whether a repo's remotes are public."""
    if not shutil.which("gh"):
        return "unknown"
    _, names = git(repo, "remote")
    seen = set()
    for name in names.decode("utf-8", "replace").split():
        _, url = git(repo, "remote", "get-url", name)
        match = re.search(r"github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url.decode("utf-8", "replace").strip())
        if not match:
            continue
        try:
            done = subprocess.run(["gh", "repo", "view", f"{match[1]}/{match[2]}", "--json", "visibility", "--jq", ".visibility"],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if done.returncode == 0:
            seen.add(done.stdout.strip().lower())
    return "public" if "public" in seen else "private" if seen else "unknown"


def action_for(secret):
    if secret["confidence"] == "low":
        return "Looks like a local development password. Review it, and delete the rule if it isn't needed."
    if secret["exposure"] == "pushed":
        if secret.get("visibility") == "private":
            return "Pushed to a private repo. Rotating it is recommended, then clean up."
        return "Rotate it now, then clean up. Don't save the old value anywhere."
    if secret["exposure"] == "committed":
        return "Committed but not pushed. Remove it from history before pushing, or rotate it."
    return "Only on this Mac. Delete the rule, and keep the value in a secrets manager if you still need it."


class Audit:
    def __init__(self, root, home):
        self.root, self.home = root, home
        self.by_value = {}
        self.pushed_cache = {}

    def show(self, path):
        return "~" + path[len(self.home):] if path.startswith(self.home + os.sep) else path

    def record(self, findings, exposure, location, repo=None):
        for where, kind, value, conf in findings:
            entry = self.by_value.setdefault(value, {"kind": kind, "confidence": conf, "exposure": exposure, "locations": [], "repos": set()})
            if CONFIDENCE_RANK[conf] < CONFIDENCE_RANK[entry["confidence"]]:
                entry.update(kind=kind, confidence=conf)
            if EXPOSURE_RANK[exposure] < EXPOSURE_RANK[entry["exposure"]]:
                entry["exposure"] = exposure
            entry["locations"].append(dict(location, where=where))
            if exposure == "pushed" and repo:
                entry["repos"].add(repo)

    def run(self, include_history, check_github):
        settings, repos, unreadable_dirs = discover(self.root)
        unreadable = 0
        for path in settings:
            document = read_settings(path)
            if document is None:
                unreadable += 1
                continue
            _, state = git_state(path)
            self.record(scan_document(document), "local", {"state": "current", "file": self.show(path), "git": state})
        if include_history:
            for repo in repos:
                for commit, path, document in history_versions(repo):
                    findings = scan_document(document)
                    if findings:
                        exposure = "pushed" if is_pushed(repo, commit, self.pushed_cache) else "committed"
                        self.record(findings, exposure, {"state": "history", "repo": self.show(repo), "commit": commit[:10], "file": path, "pushed": exposure == "pushed"}, repo)
        secrets = sorted(self.by_value.values(), key=lambda s: (EXPOSURE_RANK[s["exposure"]], CONFIDENCE_RANK[s["confidence"]], s["kind"]))
        visibility = {}
        for number, secret in enumerate(secrets, 1):
            secret["id"] = f"secret-{number}"
            repos_pushed = secret.pop("repos")
            if check_github and repos_pushed:
                seen = {visibility.setdefault(r, github_visibility(r)) for r in repos_pushed}
                secret["visibility"] = "public" if "public" in seen else "unknown" if "unknown" in seen else "private"
            secret["action"] = action_for(secret)
        return {
            "scanned": {"root": self.show(self.root), "settings_files": len(settings), "repos": len(repos), "unreadable": unreadable, "unreadable_folders": unreadable_dirs},
            "secrets": secrets,
            "limits": LIMITS,
        }


def render(report):
    scanned = report["scanned"]
    lines = [f"Scanned {scanned['settings_files']} settings files and {scanned['repos']} git repos under {scanned['root']}."]
    if scanned["unreadable"]:
        lines.append(f"{scanned['unreadable']} settings files could not be parsed and were skipped.")
    if scanned["unreadable_folders"]:
        lines.append(f"{scanned['unreadable_folders']} folders could not be read. macOS may need folder access for this terminal.")
    lines.append(f"Found {len(report['secrets'])} likely secrets. Values are never shown.")
    for secret in report["secrets"]:
        exposure = secret["exposure"] + (f", {secret['visibility']}" if secret.get("visibility") else "")
        lines += ["", f"{secret['id']}: {secret['kind']} ({secret['confidence']} confidence), {exposure}", f"  What to do: {secret['action']}"]
        for loc in secret["locations"]:
            if loc["state"] == "current":
                lines.append(f"  {loc['file']} | {loc['where']} | {loc['git']}")
            else:
                pushed = "pushed" if loc["pushed"] else "not pushed"
                lines.append(f"  {loc['repo']} | commit {loc['commit']} | {loc['file']} | {loc['where']} | {pushed}")
    lines += ["", "Limits:"] + [f"  {item}" for item in report["limits"]]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Find secrets saved in Claude Code settings files. Never prints a value.")
    parser.add_argument("root", nargs="?", default="~", help="folder to scan (default: your home folder)")
    parser.add_argument("--text", action="store_true", help="plain report (the default)")
    parser.add_argument("--json", action="store_true", help="JSON report")
    parser.add_argument("--github", action="store_true", help="ask GitHub through gh whether pushed repos are public")
    parser.add_argument("--no-history", action="store_true", help="skip git history")
    args = parser.parse_args()
    try:
        root = os.path.realpath(os.path.expanduser(args.root))
        report = Audit(root, os.path.realpath(os.path.expanduser("~"))).run(not args.no_history, args.github)
    except Exception as error:  # Never let a traceback carry file contents into the output.
        print(f"audit failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=1) if args.json else render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
