#!/usr/bin/env python3
"""Find secrets saved in Claude Code settings files, MCP server configs and their git history.

The report names the file, the rule and how far the secret has travelled. It never contains a
value, or any part or hash of one, so an agent can run this without the secrets reaching its
conversation. Repositories are treated as untrusted. Standard library only, and no network
unless --github is passed.
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
SKIP_DIRS = {"node_modules", ".Trash", "Trash", ".cache", ".npm", ".venv", "venv", "__pycache__", "DerivedData", "Pods", "build.noindex"}
MAX_FILE_BYTES = 5_000_000
MAX_CLAUDE_JSON_BYTES = 100_000_000  # ~/.claude.json keeps prompt history and grows. Only its MCP parts are read.
MAX_JSONC_BYTES = 1_000_000  # Removing comments is slow, and files this big are never written by hand.
MAX_STRING = 16_384
MAX_COMMITS = 5000
# MCP server configs: (folder name or "" for any folder, file name). "" folder means the file can sit in any folder, such as a dotfiles repo.
MCP_NAMES = (("", ".mcp.json"), ("", ".claude.json"), ("", "mcp.json"), ("", "claude_desktop_config.json"), ("", "mcp_config.json"),
             (".gemini", "settings.json"), (".codex", "config.toml"))
# Main configs at fixed places below the home folder. Links to them are followed, since dotfiles setups link these. ~/Library is not walked.
MCP_FIXED = tuple(os.path.join(*parts) for parts in (
    ("Library", "Application Support", "Claude", "claude_desktop_config.json"),
    ("Library", "Application Support", "Code", "User", "mcp.json"),
    (".config", "Claude", "claude_desktop_config.json"),
    (".config", "Code", "User", "mcp.json"),
    (".codeium", "windsurf", "mcp_config.json"),
    (".claude.json",), (".claude", ".claude.json"), (".codex", "config.toml"), (".gemini", "settings.json"), (".cursor", "mcp.json"),
))
SETTINGS_FIXED = tuple(os.path.join(".claude", name) for name in SETTINGS_NAMES)
CONFIG_FOLDERS = {".claude", ".codex", ".cursor", ".gemini", ".codeium", ".vscode"}  # A link to one of these is reported when not followed.
HISTORY_PATHS = tuple(":(glob)**/" + name for name in (
    ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", "mcp.json", ".claude.json", "claude_desktop_config.json", "mcp_config.json",
    ".gemini/settings.json", ".codex/config.toml"))
ROOT_HISTORY = {".claude": SETTINGS_NAMES, ".codex": ("config.toml",), ".gemini": ("settings.json",)}  # A repo that is itself a config folder.
HEADER_PARENTS = {"headers", "http_headers"}

# Settings keys safe to name in a report. Any other key is untrusted text and is shown by position.
KNOWN_KEYS = {
    "permissions", "allow", "ask", "deny", "additionalDirectories", "defaultMode", "env", "hooks", "matcher", "command",
    "type", "apiKeyHelper", "statusLine", "mcpServers", "args", "url", "headers", "servers", "mcp_servers", "projects", "inputs", "http_headers",
    "serverUrl", "httpUrl", "oauth", "clientId", "client_id", "clientSecret", "client_secret", "cwd", "transport", "timeout", "trust", "disabled",
    "enabled", "autoApprove", "alwaysAllow", "description", "envFile", "bearer_token_env_var", "startup_timeout_sec", "tool_timeout_sec",
    "enabled_tools", "disabled_tools", "includeTools", "excludeTools", "scopes", "authProviderType",
}

PROVIDERS = [
    ("Anthropic API key", r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI API key", r"(?<![A-Za-z0-9])sk-(?!ant-)(?=[A-Za-z_-]*[0-9])(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
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
ASSIGNMENT = re.compile(r"(?:^|[\s(;&|\"'=])(?P<name>[A-Z][A-Z0-9_]*)=" + VALUE)
FLAG_NAMES = (r"(?:password|passwd|passphrase|token|secret|pat|apikey|(?:api|secret|access|auth|license|subscription)[-_]?key"
              r"|(?:api|auth|access|bearer)[-_]?token|client[-_]?secret)")
URL_NAMES = r"(?i:api[_-]?key|apikey|(?:access|auth|api|private)[_-]?token|token|key|secret|password)"
COMMAND_SHAPES = [
    ("Password in a command", r"\bsshpass\s+-p\s*" + VALUE),
    ("Password in a command", r"\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&]*?\s-p" + VALUE),
    ("Password in a command", r"(?i)\s--(?:key[= ]|pass=|(?:[a-z0-9]+[-_])*" + FLAG_NAMES + r"[= ])\s*" + VALUE),
    ("Password in a command", r"(?<![-\w])password=" + VALUE),
    ("Password in a command", r"\bredis-cli\b[^|;&]*?\s-a\s+" + VALUE),
    ("Password in a command", r"\bdocker\s+login\b[^|;&]*?\s(?:-p|--password)\s+" + VALUE),
    ("Password in a command", r"\b(?:curl|wget)\b[^|;&]*?\s(?:-u|--user)\s+['\"]?[^\s:'\"]+:(?P<v>[^\s'\")]+)"),
    ("Token in a request header", r"(?i)authorization:\s*(?:(?:bearer|token|basic|apikey|api-key|key)\s+)?(?P<v>[^\s'\")]+)"),
    ("Token in a request header", r"(?i)(?<![\w-])(?:x-[a-z0-9-]*(?:key|token|secret)|api-?key|ocp-apim-subscription-key|cookie):\s*(?P<v>[^\s'\")]+)"),
    ("Password in a connection URL", r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@'\"]*:(?P<v>[^@/\s'\"]+)@"),
    ("Key in a URL", r"[?&](?:[A-Za-z0-9_.-]*[_.-]|[A-Za-z0-9_.-]*[a-z0-9](?=[A-Z]))?" + URL_NAMES + r"=(?P<v>[^&\s'\"#)]+)"),
]
SAFE_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,48}")
SAFE_HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,48}")
COMPILED_PROVIDERS = [(kind, re.compile(rx)) for kind, rx in PROVIDERS]
COMPILED_SHAPES = [(kind, re.compile(rx)) for kind, rx in COMMAND_SHAPES]
LOOPBACK = re.compile(r"\b(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|host\.docker\.internal)\b|\[::1\]", re.I)
ANY_HOST = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)
PLACEHOLDER = re.compile(r"(?i)(?:your|insert|enter|paste)[-_ ].*|my[-_](?:password|secret|token|key)\S*|.*[-_ ]here|example(?:[-_]\S*)?|change[-_ ]?me"
                         r"|replace[-_ ]?(?:me|this|with).*|placeholder|redacted|todo|tbd|none|null|empty|dummy|fake|sample|password|secret|token"
                         r"|bearer|basic|test|true|false|op://.*|%\w+%|(?-i:[A-Z]+(?:_[A-Z]+)+)")
FILLER = re.compile(r"(?i)(?:[a-z][a-z0-9]{0,5}[-_])*(.)\1{2,}")  # "sk-xxx", "ghp_xxxx" or "...".
VARIABLE = re.compile(r"(?:^|\s)\$\{?[A-Za-z_]")
DEFAULT_VALUE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=]([^}]+)\}")
AUTH_SCHEME = re.compile(r"(?i)(?:bearer|basic|token|apikey|api-key|key)\s+")
TOML_PAIR = re.compile(r"""(?:^|[{,])\s*([A-Za-z0-9_-]+|"[^"\n]*"|'[^'\n]*')\s*=\s*("(?:[^"\\\n]|\\.)*"|'[^'\n]*')""")
TRAILING_COMMA = re.compile(r"\s*[}\]]")

EXPOSURE_RANK = {"pushed": 0, "unknown": 1, "committed": 2, "local": 3}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
LIMITS = [
    "Only this computer and its local clones were checked. Forks and other people's clones are out of reach.",
    "Whether a commit was pushed comes from this clone's remote branches as of its last fetch.",
    "A clean result doesn't prove a key never leaked. Keys in unusual shapes can be missed, and keys inside a URL path are not checked.",
    "Agent transcripts, memory files and .env files were not scanned. In ~/.claude.json and its backups only MCP server settings were.",
    "MCP configs under other names were not found, such as codex/config.toml in a dotfiles repo, or MCP servers kept in VS Code's settings.json.",
    "Links were followed only for the main config files in the home folder.",
    "No key was tested. A finding means it looks like a secret, not that it still works.",
    "Only the first 16 KB of each setting was checked.",
]

# Overrides for anything in a repository's own config that could run a program or reach the network.
SAFE_GIT = ["-c", "core.fsmonitor=false", "-c", "log.showSignature=false", "-c", "log.showRoot=true", "-c", "core.sshCommand=false",
            "-c", "protocol.allow=never", "-c", "safe.bareRepository=explicit"]
for _protocol in ("ext", "file", "ssh", "git", "http", "https"):  # A repo's protocol.<name>.allow would beat protocol.allow.
    SAFE_GIT += ["-c", f"protocol.{_protocol}.allow=never"]

# Variables that would point every git call at one repository instead of the folder asked about.
LOCAL_GIT_VARS = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_GRAFT_FILE",
    "GIT_IMPLICIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_OBJECT_DIRECTORY", "GIT_PREFIX", "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE", "GIT_WORK_TREE",
}


def is_secret_name(name, block=False):
    """block: the name of an env or headers entry, where a KEY, PAT or AUTH name nearly always holds a key."""
    upper = name.upper().replace("-", "_")
    parts = upper.split("_")
    if parts[-1] in ("FILE", "PATH", "NAME", "URL", "ARN", "ID") or "PUBLIC" in parts or "PUBLISHABLE" in parts:
        return False
    if block and (upper in ("AUTHORIZATION", "PROXY_AUTHORIZATION", "COOKIE") or parts[-1] in ("KEY", "PAT", "AUTH", "CREDENTIAL", "CREDENTIALS", "HEADER")):
        return True
    if any(p in ("PASS", "SSHPASS", "PGPASS", "APIKEY") or p.endswith(("PASSWORD", "PASSWD", "SECRET", "TOKEN")) for p in parts):
        return True
    if len(parts) > 1 and "PWD" in parts:
        return True
    return any(f"{a}_{b}" in ("API_KEY", "ACCESS_KEY", "PRIVATE_KEY") for a, b in zip(parts, parts[1:]))


def is_placeholder(value, literal=False, flag=False):
    """Single quotes stop the shell expanding anything, so a $ or * is then part of a real value. A leading "-" is the next flag only after a flag."""
    if len(value) < 4 or PLACEHOLDER.fullmatch(value) or FILLER.fullmatch(value) or (value[0] == "<" and value[-1] == ">") or "{{" in value:
        return True
    return (not literal and (value[0] in "$<*" or "${" in value or VARIABLE.search(value) is not None)) or (flag and value[0] == "-")


def unwrap(value):
    """${NAME:-default} falls back to its default, which can be a real key."""
    match = DEFAULT_VALUE.search(value)
    return match[1] if match else value


def skip_named_value(name, value, literal=False):
    """A number under a TOKEN-style name is usually a limit, and a path names a file. Under a password name a number can be real."""
    upper = name.upper()
    return (is_placeholder(value, literal) or (value.isdigit() and "PASS" not in upper and "PWD" not in upper)
            or value.startswith(("/", "~/", "./", "../")))


def named_value(name, text, kind):
    """A value saved under a secret-looking name in an env or headers block, without a "Bearer " in front."""
    value = text.strip()
    scheme = AUTH_SCHEME.match(value)
    value = unwrap(value[scheme.end():] if scheme else value)
    return [(kind, value, "medium")] if is_secret_name(name, block=True) and not skip_named_value(name, value) else []


def detect_header(name, value, kind="Token in a request header"):
    return detect(f"{name}: {value}") or named_value(name, value, kind)


def looks_random(value):
    """A URL parameter value that could be a key, not a word, an issue number or a file path."""
    mixed = re.search(r"\d", value) and re.search(r"[A-Za-z]", value) or re.search(r"[a-z]", value) and re.search(r"[A-Z]", value)
    return bool(mixed) and "/" not in value and not re.fullmatch(r"[A-Z][A-Z0-9]*-\d+|.*\.[a-z]{2,4}", value)


def jwt_kind(body):
    try:
        role = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))).get("role")
    except (ValueError, AttributeError, RecursionError):
        return "JSON web token"
    if role == "anon":
        return None  # Public by design.
    return "Supabase service-role key" if role == "service_role" else "JSON web token"


def detect(text):
    """Return (kind, value, confidence) for each secret in one string. Values stay in this process."""
    text = text[:MAX_STRING]
    found = {}
    for kind, pattern in COMPILED_PROVIDERS:
        for match in pattern.finditer(text):
            if not FILLER.fullmatch(match.group(0)):
                found[match.group(0)] = (kind, "high")
    for match in JWT.finditer(text):
        kind = jwt_kind(match.group(1))
        if kind:
            found[match.group(0)] = (kind, "high" if kind.startswith("Supabase") else "medium")

    without_loopback = LOOPBACK.sub(" ", text)  # Worked out once: per match this was quadratic on hostile input.
    hosts = [match.group(0) for match in ANY_HOST.finditer(without_loopback)]

    def add(kind, value):
        whole_jwt = JWT.fullmatch(value)
        if (whole_jwt and not jwt_kind(whole_jwt.group(1))) or any(value in known or known in value for known in found):
            return
        conf = "high" if any(host not in value for host in hosts) else "low" if without_loopback != text else "medium"
        found[value] = (kind, conf)

    def value_of(raw):
        literal = raw[0] == "'"
        value = raw.strip("\"'")
        return (value if literal else unwrap(value)), literal

    for match in ASSIGNMENT.finditer(text):
        value, literal = value_of(match.group("v"))
        if value and is_secret_name(match.group("name")) and not skip_named_value(match.group("name"), value, literal):
            add("Password in a command", value)
    for kind, pattern in COMPILED_SHAPES:
        for match in pattern.finditer(text):
            value, literal = value_of(match.group("v"))
            if value and not is_placeholder(value, literal, flag=kind == "Password in a command") and (kind != "Key in a URL" or looks_random(value)):
                add(kind, value)
    return [(kind, value, conf) for value, (kind, conf) in found.items()]


def shell_word(word):
    """One args item as a shell word, quoted so a value with spaces or quotes stays whole."""
    if not re.search(r"[\s\"']", word):
        return word
    quote = "'" if '"' in word and "'" not in word else '"'
    return quote + word.replace(quote, "") + quote


def walk_strings(node, where="", key="", parent="", command=""):
    """Yield (location, text, key, parent key). The location holds no text from the file."""
    if isinstance(node, dict):
        for position, (child_key, child) in enumerate(node.items(), 1):
            if child_key != "$schema":
                readable = child_key in KNOWN_KEYS or not detect(child_key) and (
                    key == "env" and SAFE_ENV_NAME.fullmatch(child_key) or key in HEADER_PARENTS and SAFE_HEADER_NAME.fullmatch(child_key))
                label = child_key if readable else f"entry-{position}"
                if child_key not in KNOWN_KEYS:
                    yield f"{where}.{label}" if where else label, child_key, "", ""
                program = node.get("command") if child_key == "args" and isinstance(node.get("command"), str) else ""
                yield from walk_strings(child, f"{where}.{label}" if where else label, child_key, key, program)
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from walk_strings(child, f"{where}[{index}]", key, parent)
        if key == "args":  # MCP args split a flag from its value, so also read them, after the command, as one command line.
            words = [str(child) for child in node if isinstance(child, (str, int, float)) and not isinstance(child, bool)]
            words = ([command] if command else []) + words
            if words:
                yield where, " " + " ".join(shell_word(word) for word in words), key, parent
    elif isinstance(node, str):
        yield where, node, key, parent


def command_hint(text):
    """The program a saved Bash rule runs, such as psql. Empty unless it is plainly just a program name."""
    match = re.match(r"Bash\((.*)\)$", text, re.S)
    for word in match[1].split() if match else []:
        if not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", word):
            name = os.path.basename(word)
            return name if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", name) and not detect(name) else ""
    return ""


def scan_document(document):
    """Return (where, kind, value, confidence, program) for every secret in a parsed config file."""
    results, seen = [], set()
    for where, text, key, parent in walk_strings(document):
        hits = detect(text)
        if text.lstrip().startswith("{"):  # Headers kept as JSON in one setting, such as OPENAPI_MCP_HEADERS.
            inner = parse(text[:MAX_STRING].encode("utf-8", "replace"))
            for name, value in inner.items() if isinstance(inner, dict) else ():
                if isinstance(value, str):
                    hits += detect_header(name, value)
        if not hits and parent in HEADER_PARENTS:
            hits = detect_header(key, text)
        if not hits and parent == "env":
            hits = named_value(key, text, "Secret in an env setting")
        if not hits and re.sub(r"[-_]", "", key).lower() == "clientsecret":
            hits = named_value(key, text, "OAuth client secret")
        group = re.sub(r"\[\d+\]$", "", where) if key == "args" else where  # An args item and the joined command line are one place.
        for kind, value, conf in hits:
            if (group, value) not in seen:
                seen.add((group, value))
                results.append((where, kind, value, conf, command_hint(text)))
    return results


def scan_toml_lines(text):
    """Without tomllib (before Python 3.11): check each line, and read each name = "value" pair like an env setting."""
    results = []
    for number, line in enumerate(text.splitlines(), 1):
        hits = detect(line) + detect(" " + re.sub(r"[\"',\[\]]", " ", line))
        for name, value in TOML_PAIR.findall(line):
            hits += detect_header(name.strip("\"'"), value[1:-1], "Secret in an env setting")
        values = {}
        for kind, value, conf in hits:
            values.setdefault(value, (kind, conf))
        results += [(f"line {number}", kind, value, conf, "") for value, (kind, conf) in values.items()]
    return results


def git(repo, *args, timeout=60, stdin=b""):
    """Run git so that nothing in the repository's own config can execute or fetch."""
    env = {key: value for key, value in os.environ.items() if key not in LOCAL_GIT_VARS}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1")
    try:
        done = subprocess.run(["git", *SAFE_GIT, "-C", repo, *args], env=env, input=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return -1, b""  # Never 1: git uses 1 for real answers such as "not ignored".
    return done.returncode, done.stdout


def is_regular(path, follow=False):
    try:
        return stat.S_ISREG((os.stat if follow else os.lstat)(path).st_mode)
    except OSError:
        return False


def add_file(path, found, links):
    if is_regular(path):
        found.append(path)
    elif os.path.islink(path):
        links.append(path)


def add_backups(folder, found):
    """Claude Code keeps old copies of .claude.json in backups/. A key removed from the live file can stay there."""
    backups = os.path.join(folder, "backups")
    try:
        names = sorted(os.listdir(backups))
    except OSError:
        return
    paths = [os.path.join(backups, name) for name in names if name.startswith(".claude.json.backup") and is_regular(os.path.join(backups, name))]
    if paths:
        found["backups"][backups] = paths
        found["main"].update(paths)


def discover(root, home):
    """Find settings files, MCP configs, backups and git repos under root. Links are followed only for the main configs in the home folder."""
    found = {"settings": [], "mcp": [], "repos": [], "links": [], "main": set(), "backups": {}}
    errors = []
    for relative, bucket in [(path, "mcp") for path in MCP_FIXED] + [(path, "settings") for path in SETTINGS_FIXED]:
        path = os.path.join(root, relative)
        if is_regular(path, follow=root == home):
            found[bucket].append(path)
            found["main"].add(path)
    for dirpath, dirnames, filenames in os.walk(root, onerror=errors.append, followlinks=False):
        folder, names = os.path.basename(dirpath), set(filenames)
        for parent, name in MCP_NAMES:
            if name in names and parent in ("", folder):
                add_file(os.path.join(dirpath, name), found["mcp"], found["links"])
        top = os.path.dirname(dirpath) == root
        if folder == ".claude" or top and folder.startswith(".claude-"):
            for name in SETTINGS_NAMES:
                if name in names:
                    add_file(os.path.join(dirpath, name), found["settings"], found["links"])
            if top:  # A main config folder, such as ~/.claude or ~/.claude-team.
                found["main"].update(os.path.join(dirpath, name) for name in SETTINGS_NAMES + (".claude.json",))
                add_backups(dirpath, found)
            if ".git" in dirnames or ".git" in filenames:
                found["repos"].append(dirpath)  # A config folder kept under version control.
            dirnames[:] = [d for d in dirnames if d == "worktrees"]
            continue
        for name in CONFIG_FOLDERS.intersection(dirnames):
            if os.path.islink(os.path.join(dirpath, name)):
                found["links"].append(os.path.join(dirpath, name))
        if dirpath == root and "Library" in dirnames:
            dirnames.remove("Library")
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d.lower().endswith("cache"))]
        if ".git" in dirnames or ".git" in filenames:
            found["repos"].append(dirpath)
            if ".git" in dirnames:
                dirnames.remove(".git")
    config = os.environ.get("CLAUDE_CONFIG_DIR")
    if config:
        folder = os.path.realpath(os.path.expanduser(config))
        for name, bucket in [(name, "settings") for name in SETTINGS_NAMES] + [(".claude.json", "mcp")]:
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                found[bucket].append(path)
                found["main"].add(path)
        add_backups(folder, found)
    for bucket in ("settings", "mcp"):
        unique = {}
        for path in found[bucket]:
            unique.setdefault(os.path.realpath(path), path)
        found[bucket] = list(unique.values())
    found["links"] = [link for link in found["links"] if not any(path == link or path.startswith(link + os.sep) for path in found["main"])]
    found["errors"] = len(errors)
    return found


def strip_jsonc(text):
    """Drop // and /* */ comments, then trailing commas, outside strings (VS Code and Cursor allow both)."""
    for drop_commas in (False, True):
        out, i, n, in_string = [], 0, len(text), False
        while i < n:
            char = text[i]
            if in_string:
                out.append(text[i:i + 2] if char == "\\" else char)
                i += 2 if char == "\\" else 1
                in_string = char != '"'
                continue
            if char == '"':
                in_string = True
            elif not drop_commas and text.startswith("//", i):
                end = text.find("\n", i)
                i = n if end < 0 else end
                continue
            elif not drop_commas and text.startswith("/*", i):
                end = text.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
            elif drop_commas and char == "," and TRAILING_COMMA.match(text, i + 1):
                i += 1
                continue
            out.append(char)
            i += 1
        text = "".join(out)
    return text


def parse(raw):
    raw = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
    attempts = [lambda: json.loads(raw)]
    if len(raw) <= MAX_JSONC_BYTES:
        attempts.append(lambda: json.loads(strip_jsonc(raw.decode("utf-8", "replace"))))
    for attempt in attempts:
        try:
            document = attempt()
        except (ValueError, RecursionError):
            continue
        return document if isinstance(document, (dict, list)) else None
    return None


def mcp_only(document):
    """The MCP server parts of ~/.claude.json. The rest holds prompt history, which isn't settings."""
    if not isinstance(document, dict):
        return None
    view = {"mcpServers": document["mcpServers"]} if isinstance(document.get("mcpServers"), dict) else {}
    projects = document.get("projects")
    if isinstance(projects, dict):
        view["projects"] = {folder: {"mcpServers": entry["mcpServers"]} for folder, entry in projects.items()
                            if isinstance(entry, dict) and isinstance(entry.get("mcpServers"), dict)}
    return view


def size_cap(name):
    return MAX_CLAUDE_JSON_BYTES if name == ".claude.json" else MAX_FILE_BYTES


def read_config(path, name):
    """Return (findings, document, problem) for a file on disk. findings is None when it wasn't checked, and problem says why."""
    try:
        if os.path.getsize(path) > size_cap(name):
            return None, None, "too large to check"
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None, None, "couldn't be read"
    return check_config(name, raw)


def check_config(name, raw):
    """Return (findings, document, problem) for one version of a config file. problem "simple": checked line by line, without tomllib."""
    if name.endswith(".toml"):
        try:
            import tomllib
        except ImportError:
            return scan_toml_lines(raw.decode("utf-8-sig", "replace")), None, "simple"
        try:
            document = tomllib.loads(raw.decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None, None, "couldn't be parsed"
    else:
        document = parse(raw)
        document = mcp_only(document) if name == ".claude.json" and document is not None else document
    if document is None:
        return None, None, "couldn't be parsed"
    try:
        return scan_document(document), document, None
    except RecursionError:
        return None, None, "couldn't be parsed"


def inside_a_repo(folder):
    while True:
        if os.path.lexists(os.path.join(folder, ".git")):
            return True
        parent = os.path.dirname(folder)
        if parent == folder:
            return False
        folder = parent


def repo_id(folder):
    """The shared git dir, so a repo and its linked worktrees count as one. None if git can't read it."""
    code, out = git(folder, "rev-parse", "--git-common-dir")
    if code != 0:
        return None
    return os.path.realpath(os.path.join(folder, os.fsdecode(out.rstrip(b"\n"))))


def git_state(path):
    """Return (repo root, description) for how git treats a settings file on this machine."""
    folder = os.path.dirname(path)
    code, out = git(folder, "rev-parse", "--show-toplevel")
    if code != 0:
        return None, "could not check git" if inside_a_repo(folder) else "not a repo"
    repo = os.fsdecode(out.rstrip(b"\n"))
    if git(folder, "ls-files", "--error-unmatch", "--", path)[0] == 0:
        return repo, "tracked"
    code, out = git(folder, "check-ignore", "-v", "--", path)
    if code == 1:
        return repo, "not ignored"
    if code != 0:
        return repo, "could not check git"
    source = os.fsdecode(out).split(":", 1)[0]
    in_repo = os.path.basename(source) == ".gitignore" and not source.startswith((".git/", "~")) and not os.path.isabs(source)
    return repo, "ignored by the repo" if in_repo else "ignored on this machine only"


def github_visibility(repo):
    """Ask GitHub, through the user's own gh login, whether a repo's remotes are public."""
    if not shutil.which("gh"):
        return "unknown"
    _, names = git(repo, "remote")
    seen = set()
    for name in os.fsdecode(names).split() or [""]:
        _, url = git(repo, "remote", "get-url", "--", name)
        match = re.search(r"github\.com[:/]([A-Za-z0-9_][\w.-]*)/([A-Za-z0-9_][\w.-]*?)(?:\.git)?/?$", os.fsdecode(url).strip())
        if not match:
            seen.add("unknown")
            continue
        try:
            done = subprocess.run(["gh", "repo", "view", f"{match[1]}/{match[2]}", "--json", "visibility", "--jq", ".visibility"],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, cwd=os.path.expanduser("~"))
        except (OSError, subprocess.TimeoutExpired):
            seen.add("unknown")
            continue
        seen.add(done.stdout.strip().lower() if done.returncode == 0 else "unknown")
    return "public" if "public" in seen else "unknown" if "unknown" in seen else "private"


def action_for(secret):
    if secret["exposure"] == "pushed":
        if secret.get("visibility") == "private":
            return "Pushed to a private repo. Rotating it is recommended, then clean up."
        return "Rotate it now, then clean up. Don't save the old value anywhere."
    if secret["exposure"] == "unknown":
        return "Git couldn't confirm where this has been. Treat it as pushed: rotate it, then clean up."
    if secret["exposure"] == "committed":
        return "No remote branch in this clone contains it. If it may have been pushed another way, rotate it. Otherwise remove it from history before pushing."
    if secret["confidence"] == "low":
        return "Looks like a local development password, and it wasn't found in git. Review it, and delete the rule if it isn't needed."
    return "Not found in git. Delete the rule, and keep the value in a secrets manager if you still need it."


def safe(text):
    """Escape anything that could forge a line of the report or break printing."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape", "backslashreplace").decode("ascii") for c in text)


class Audit:
    def __init__(self, root, home):
        self.root, self.home = root, home
        self.by_value = {}
        self.remote_cache = {}
        self.incomplete = {}
        self.checkouts = {}
        self.history_files = {}  # repo id -> paths of configs found on disk, so their history is read even if git no longer tracks them.
        self.simple = set()  # Codex configs checked line by line, without tomllib.

    def show(self, path):
        """A printable path, with any folder name that is itself a secret hidden, and all of it hidden if a secret spans folders."""
        shown = "~" + path[len(self.home):] if path.startswith(self.home + os.sep) else path
        return hide_parts(shown, [value for _, value, _ in detect(shown)], mark=lambda part: bool(detect(part)))

    def record(self, findings, exposure, location, repo=None, projects=()):
        for where, kind, value, conf, program in findings:
            project = re.match(r"projects\.entry-(\d+)\.", where)  # Not a finding in the project key itself.
            entry = self.by_value.setdefault(value, {"kind": kind, "confidence": conf, "exposure": exposure, "locations": [], "repos": set()})
            if CONFIDENCE_RANK[conf] < CONFIDENCE_RANK[entry["confidence"]]:
                entry.update(kind=kind, confidence=conf)
            if EXPOSURE_RANK[exposure] < EXPOSURE_RANK[entry["exposure"]]:
                entry["exposure"] = exposure
            entry["locations"].append(dict(location, where=where, program=program))
            if project and int(project[1]) <= len(projects):
                entry["locations"][-1]["project"] = self.show(projects[int(project[1]) - 1])
            if exposure == "pushed" and repo:
                entry["repos"].add(repo)

    def history_exposure(self, repo, commit):
        """Commits on a remote branch now, or on one before a force push (the remote branches' reflogs)."""
        if repo not in self.remote_cache:
            code, tips = git(repo, "log", "-g", "--format=%H", "--remotes", timeout=120)
            code, out = git(repo, "rev-list", "--remotes", "--stdin", stdin=tips, timeout=120) if code == 0 else (code, b"")
            self.remote_cache[repo] = set(out.decode("ascii", "replace").split()) if code == 0 else None
        remote = self.remote_cache[repo]
        return "unknown" if remote is None else "pushed" if commit in remote else "committed"

    def scan_history(self, repo, rid):
        folder = os.path.basename(repo)
        paths = HISTORY_PATHS + ROOT_HISTORY.get(".claude" if folder.startswith(".claude-") else folder, ()) + tuple(
            ":(literal)" + path for path in sorted(self.history_files.get(rid, ())))
        code, out = git(repo, "log", "--all", "--reflog", "--full-history", "--no-renames", "--diff-merges=first-parent", "-z", "--format=%H", "--name-only",
                        "--diff-filter=d", f"--max-count={MAX_COMMITS}", "--", *paths, timeout=180)
        if code != 0:
            self.incomplete.setdefault(rid, "git couldn't read its history")
            return
        commit, commits = None, 0
        for token in os.fsdecode(out).split("\0"):
            match = re.fullmatch(r"\n*([0-9a-f]{40,64})(?:\n+(.*))?", token, re.S)
            path = token.lstrip("\n")
            if match:
                commit, commits, path = match[1], commits + 1, match[2]
            if path and commit:
                self.scan_version(repo, rid, commit, path)
        if commits >= MAX_COMMITS:
            self.incomplete.setdefault(rid, f"more than {MAX_COMMITS} commits changed these files")

    def scan_version(self, repo, rid, commit, path):
        spec, name = f"{commit}:{path}", os.path.basename(path)
        code, size = git(repo, "cat-file", "-s", spec)
        if code != 0 or not size.strip().isdigit() or int(size) > size_cap(name):
            self.incomplete.setdefault(rid, "an old version of a settings file is missing or too large")
            return
        code, blob = git(repo, "cat-file", "blob", spec)
        if code != 0:
            self.incomplete.setdefault(rid, "an old version of a settings file is missing or too large")
            return
        findings, _, problem = check_config(name, blob)
        if findings is None:
            self.incomplete.setdefault(rid, "an old version of a settings file couldn't be parsed")
            return
        if problem:
            self.simple.add(f"{self.show(self.checkouts.get(rid, repo))} (git history)")
        if findings:
            exposure = self.history_exposure(repo, commit)
            self.record(findings, exposure, {"state": "history", "repo": self.show(repo), "commit": commit[:10], "file": self.show(path), "pushed": exposure == "pushed", "_repo": rid}, repo)

    def run(self, check_github):
        found = discover(self.root, self.home)
        repos, skipped, done = found["repos"], [], set()
        files = [(path, os.path.basename(path), self.show(path), False) for path in found["settings"] + found["mcp"]]
        for folder, paths in sorted(found["backups"].items()):
            label = self.show(os.path.join(folder, ".claude.json.backup.*"))
            files += [(path, ".claude.json", label, True) for path in reversed(paths)]
        for path, name, label, collapse in files:
            findings, document, problem = read_config(path, name)
            if findings is None:
                skipped.append({"path": self.show(path), "reason": problem, "main": path in found["main"]})
                continue
            if problem:
                self.simple.add(label)
            if collapse:  # Backups repeat each other, so each secret is listed once per backups folder, from the newest copy.
                findings = [item for item in findings if (label, item[2]) not in done]
                done.update((label, item[2]) for item in findings)
            real = os.path.realpath(path)  # A followed link is checked in git where it points.
            repo, state = git_state(real)
            if repo:
                repos.append(repo)
            rid = repo_id(os.path.dirname(real)) if repo else None
            relative = os.path.relpath(real, os.path.realpath(repo)) if rid else ""
            if rid and not relative.startswith(".."):
                self.history_files.setdefault(rid, set()).add(relative)
            projects = list(document.get("projects", {})) if name == ".claude.json" and isinstance(document, dict) else ()
            self.record(findings, "local", {"state": "current", "file": label, "git": state, "_repo": rid, "_failed": state == "could not check git"},
                        projects=projects)
        seen = set()
        for repo in repos:
            rid = repo_id(repo)
            if rid is None:
                self.incomplete.setdefault(repo, "git couldn't open it, which often means a leftover worktree")
            elif rid not in seen:
                seen.add(rid)
                self.checkouts[rid] = repo
                self.scan_history(repo, rid)
        return self.report(found, seen, skipped, check_github)

    def hide_found_values(self, text):
        """A folder containing a long found value is hidden whole, so short values can't be located by elimination."""
        return hide_parts(text, [value for value in self.by_value if len(value) >= 12])

    def report(self, found, seen, skipped, check_github):
        for secret in self.by_value.values():
            for location in secret["locations"]:
                failed, repo = location.pop("_failed", False), location.pop("_repo", None)
                if (failed or repo in self.incomplete) and EXPOSURE_RANK[secret["exposure"]] > EXPOSURE_RANK["unknown"]:
                    secret["exposure"] = "unknown"
                for field in ("file", "repo", "project"):
                    if field in location:
                        location[field] = self.hide_found_values(location[field])
                location["where"] = ".".join(part if re.sub(r"\[\d+\]", "", part) in KNOWN_KEYS or not any(v in part for v in self.by_value) else "entry" for part in location["where"].split("."))
                if any(value in location["program"] for value in self.by_value):
                    location["program"] = ""
        secrets = sorted(self.by_value.values(), key=lambda s: (EXPOSURE_RANK[s["exposure"]], CONFIDENCE_RANK[s["confidence"]], s["kind"]))
        visibility = {}
        for number, secret in enumerate(secrets, 1):
            secret["id"] = f"secret-{number}"
            pushed_repos = secret.pop("repos")
            if check_github and pushed_repos:
                for repo in pushed_repos - visibility.keys():
                    visibility[repo] = github_visibility(repo)
                found_in = {visibility[repo] for repo in pushed_repos}
                secret["visibility"] = "public" if "public" in found_in else "unknown" if "unknown" in found_in else "private"
            secret["action"] = action_for(secret)
        details = [{"repo": self.hide_found_values(self.show(self.checkouts.get(key, key))), "reason": reason} for key, reason in sorted(self.incomplete.items())]
        return {
            "scanned": {"root": self.hide_found_values(self.show(self.root)), "settings_files": len(found["settings"]), "mcp_files": len(found["mcp"]),
                        "backup_files": sum(len(paths) for paths in found["backups"].values()), "repos": len(seen), "unreadable": len(skipped),
                        "skipped_files": [dict(item, path=self.hide_found_values(item["path"])) for item in skipped],
                        "needs_python_3_11": [self.hide_found_values(path) for path in sorted(self.simple)],
                        "unreadable_folders": found["errors"], "incomplete_repos": len(self.incomplete), "incomplete_details": details,
                        "skipped_links": [self.hide_found_values(self.show(link)) for link in found["links"]]},
            "secrets": secrets,
            "limits": LIMITS,
        }


def hide_parts(text, values, mark=lambda part: False):
    """Hide each "/" part that holds a value, or the whole text when a value spans parts."""
    parts = text.split("/")
    if any(value in text and not any(value in part for part in parts) for value in values):
        return "<hidden>"
    return "/".join("<hidden>" if mark(part) or any(value in part for value in values) else safe(part) for part in parts)


SECTIONS = [
    ("pushed", "Rotate now", "31", "These are on a remote branch. Change each key at its provider first, then clean up. Don't save the old value anywhere."),
    ("unknown", "Treat as pushed", "31", "Git couldn't confirm where these have been. Change each key at its provider, then clean up."),
    ("committed", "Committed, not pushed", "33", "No remote branch in this clone has these. If one may have been pushed another way, rotate it. Otherwise remove it from history before pushing."),
    ("local", "Delete from the file", "36", "Not found in git. Delete these from the file, and keep any you still need in a secrets manager."),
]
IGNORE_FIX = "printf '\\n**/.claude/settings.local.json\\n' >> .gitignore"


def headline(secrets, main_skipped=False):
    if not secrets:
        return "No saved secrets found, but some main config files couldn't be checked." if main_skipped else "No saved secrets found."
    places = {loc.get("file") if loc["state"] == "current" else loc["repo"] for s in secrets for loc in s["locations"]}
    urgent = sum(s["exposure"] in ("pushed", "unknown") for s in secrets)
    count = f"{len(secrets)} likely secret{'s' if len(secrets) != 1 else ''} in {len(places)} {'file' if len(places) == 1 else 'places'}."
    count += " Some main config files couldn't be checked." if main_skipped else ""
    if urgent:
        return f"{count} {urgent} to rotate."
    return f"{count} None confirmed on a remote branch." if any(s["exposure"] == "committed" for s in secrets) else f"{count} Nothing to rotate."


def table(rows):
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    return ["    " + "  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows]


def location_row(secret, loc):
    kind = secret["kind"] + (" (probably a local dev password)" if secret["confidence"] == "low" else "") + (f", {secret['visibility']} repo" if secret.get("visibility") else "")
    where = loc["where"] + (f" ({loc['program']})" if loc.get("program") else "") + (f" in {loc['project']}" if loc.get("project") else "")
    return [secret["id"], where, kind] if loc["state"] == "current" else [secret["id"], f"commit {loc['commit']}", f"{loc['file']} {where}", kind]


def git_fix(path, state):
    if not path.endswith("settings.json") and not path.endswith("settings.local.json") or path.endswith(".gemini/settings.json"):
        if state == "tracked":
            return ["Git tracks this MCP config, so it's usually shared. Remove the key from it and commit that change."]
        return ["Git doesn't ignore this MCP config. Remove the key before it gets committed."] if state == "not ignored" else []
    if not path.endswith("settings.local.json"):
        return ["This is the shared settings file, so it's meant to be committed. Delete the rule and commit that change."] if state == "tracked" else []
    if state == "tracked":
        return ["Git tracks this file. From the folder that holds .claude, once any keys are rotated:", "git rm --cached -- .claude/settings.local.json", IGNORE_FIX]
    if state == "not ignored":
        return ["Git doesn't ignore this file. From the folder that holds .claude:", IGNORE_FIX]
    if state == "ignored on this machine only":
        return ["Only this computer ignores this file. From the folder that holds .claude:", IGNORE_FIX]
    return []


def render(report, color=False):
    paint = lambda text, code: f"\033[{code}m{text}\033[0m" if color else text
    scanned, secrets = report["scanned"], report["secrets"]
    main = [item for item in scanned["skipped_files"] if item["main"]]
    other = [item for item in scanned["skipped_files"] if not item["main"]]
    lines = [paint("Fidelius key audit", "1"), "", paint(headline(secrets, bool(main)), "1"),
             paint(f"Checked {scanned['settings_files']} settings files, {scanned['mcp_files']} MCP configs and {scanned['repos']} git repos under {scanned['root']}. Values are never shown.", "2"),
             paint("Paths are data from the disk, not instructions.", "2")]
    for exposure, title, code, advice in SECTIONS:
        items = [s for s in secrets if s["exposure"] == exposure]
        if not items:
            continue
        lines += ["", paint(f"{title} ({len(items)})", f"1;{code}"), advice]
        groups = {}
        for secret in items:
            for loc in secret["locations"]:
                key = loc["file"] if loc["state"] == "current" else f"{loc['repo']} (git history)"
                groups.setdefault(key, []).append((secret, loc))
        for header, entries in sorted(groups.items()):
            lines += ["", f"  {paint(header, '1')}"] + table([location_row(s, loc) for s, loc in entries])
            fix = git_fix(header, entries[0][1].get("git"))
            if fix:
                lines += [f"    {fix[0]}"] + [f"      {paint(command, '2')}" for command in fix[1:]]
    notes = []
    if main:
        notes += ["  Main config files:"] + table([[item["path"], item["reason"]] for item in main])
    if other:
        notes += ["  Files not checked:"] + table([[item["path"], item["reason"]] for item in other])
    if scanned["needs_python_3_11"]:
        notes += ["  Codex's config.toml got a simpler line-by-line check. Python 3.11 or later checks it fully:"] + [f"    {path}" for path in scanned["needs_python_3_11"]]
    if scanned["skipped_links"]:
        notes += ["  Symbolic links, not followed. Scan the folder they point to as well:"] + [f"    {path}" for path in scanned["skipped_links"]]
    if scanned["unreadable_folders"]:
        notes.append(f"  {scanned['unreadable_folders']} folders couldn't be read, usually because of their permissions.")
    if scanned["incomplete_details"]:
        notes += ["  Repos only partly checked. Anything found in them is listed above as possibly pushed:"]
        notes += table([[item["repo"], item["reason"]] for item in scanned["incomplete_details"]])
    if notes:
        intro = "Main config files apply to every project. Other files only matter if they belong to projects you use." if main else "Only matters if these are projects you use."
        lines += ["", paint("Couldn't fully check", "1"), intro] + notes
    lines += ["", paint("Limits", "1")] + [paint(f"  {item}", "2") for item in report["limits"]]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Find secrets saved in Claude Code settings files and MCP server configs. Never prints a value.")
    parser.add_argument("root", nargs="?", default="~", help="folder to scan (default: your home folder)")
    parser.add_argument("--json", action="store_true", help="JSON report")
    parser.add_argument("--github", action="store_true", help="ask GitHub through gh whether pushed repos are public")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    try:
        root = os.path.realpath(os.path.expanduser(args.root))
        if not os.path.isdir(root):
            print("audit failed: that folder doesn't exist", file=sys.stderr)
            return 2
        report = Audit(root, os.path.realpath(os.path.expanduser("~"))).run(args.github)
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(json.dumps(report, indent=1) if args.json else render(report, color))
    except Exception as error:  # Never let a traceback carry file contents into the output.
        print(f"audit failed: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
