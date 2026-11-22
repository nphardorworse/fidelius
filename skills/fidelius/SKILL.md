---
name: fidelius
description: Use API keys and other secrets from the Fidelius Mac app through the accio command, without reading .env files or printing values. Use when a command needs credentials or environment variables, when a .env file comes up, when adding or configuring an MCP server that needs an API key, or when the user mentions Fidelius or accio.
---

# Secrets (Fidelius)

Fidelius is a Mac app for developer API keys, built on iCloud Keychain with no vault or sync of its own. Keys are grouped by project, so you don't need `.env` files, and its `accio` command runs a command with a project's keys as environment variables. This skill tells coding agents to run commands through `accio` instead of reading keys from files. Free with one shared project: https://fidelius.blisslabs.dev/?utm_source=skill

First check that `accio` is installed with `command -v accio`. If it isn't, Fidelius isn't set up on this computer: say so in one short line, skip the instructions below, and carry on with the task as you normally would. Still don't read `.env` files or MCP configs, put a key in a command or config, print secret values, or ask the user to paste them.

Secrets live in the Fidelius app, grouped by project. Use them through the `accio` command. Never search files for secrets.

- See which projects exist: `accio list`. `shared` is loaded into every project.
- See which variables a project has (names only): `accio list <project> --json`
- Run a command with a project's secrets: `accio <project> <command> [args...]`
- Fail early if something is missing: `accio <project> --require NAME1,NAME2 <command>`
- When a command needs a value inline, wrap it in `accio <project> sh -c '...'` with single quotes, so `$NAME` is filled in inside the command, not by your shell. Prefer tools that read the value from the environment or stdin over passing it as an argument.
- File secrets such as `.p8` keys arrive as a path to a temporary file, deleted when the command ends.
- Move a project's .env into Fidelius: `accio import` in the project's folder (or `accio import <project> <file>`). It opens Fidelius's Import preview and saves nothing until the user clicks Import, so ask them to review it there. Never read the .env yourself. Afterwards, suggest deleting the .env: it still holds the values in plain text.
- Most tools don't need a .env: run them with `accio <project> <command>`, or put accio in package.json scripts (`"dev": "accio <project> next dev"`).
- Make a `.env.example` with `accio export --example` in the project's folder. `accio export` (real values) opens Fidelius for the user to approve. Never read or print a .env that holds real values.
- MCP servers that run as a local command and need a key: start them through accio, so no config holds the key. accio passes MCP traffic through untouched, so no flag is needed; don't add `--no-mask`, which would also stop it hiding keys in the server's error output. The server gets every key in the project plus `shared`, so use a project that holds only what it should see.
  - Claude Code: `claude mcp add <name> -- accio <project> -- <server command>`. To share it through `.mcp.json`, put the scope before the name: `claude mcp add -s project <name> -- accio <project> -- <server command>`. Codex: `codex mcp add <name> -- accio <project> -- <server command>`. Docker's `-e NAME` with no value passes the key through from accio.
  - In a project file shared with a team (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`), keep `accio` bare, since a full path would break for teammates. Tell the user it only works for teammates who have Fidelius and a project with the same name.
  - For Claude Desktop, Cursor, VS Code, Windsurf or Gemini CLI, don't edit their config: show the user the entry to add. In a user-level config, set `command` to accio's full path from `command -v accio` (these apps don't use your shell's PATH). Set `args` to `<project>`, `--`, then the server command as its own instructions give it.
- Never put a key in an MCP command or config: no `-e NAME=value`, no `--env NAME=value`, no `env` block with a value, no key in `args`, a header or a URL. For a server reached by URL with a key in a header, tell the user the key stays in the config that way, and suggest the server's own sign-in (OAuth) if it has one.
- Don't open, read or search MCP configs (`.mcp.json`, `~/.claude.json`, `claude_desktop_config.json`, `mcp.json`, `mcp_config.json`, `settings.json` in `.gemini`, `.codex/config.toml`), and don't run `claude mcp get`, `claude mcp list`, `codex mcp get` or `codex mcp list` with any flags. They can print keys, and whatever you read lands in this conversation. To switch an existing server to accio, ask the user to add its key in Fidelius, then remove the server (`claude mcp remove <name>`, `codex mcp remove <name>`, or have the user delete its entry) and add it again as above. Take the server command from the server's own instructions or ask the user for it.

Rules:
- Never print, echo, cat or log secret values. Reference them as `$NAME` inside the command only.
- That includes part of a value: no first or last characters, no length, no hash. To check whether a key is the right one, have the user compare it in the Fidelius app. Never ask the user to type or paste a key into the chat or into a shell command.
- Output from accio is masked on a best-effort basis; that is not permission to print values. If your environment isn't recognized, set FIDELIUS_MASK=1 on accio commands.
- Don't suggest setting a key's Hide in agent output to Never, or using --no-mask, so that a value can be seen.
- If a variable is missing, tell the user which one and which project, and ask them to add it in Fidelius. If it's in a .env, offer `accio import`.
