---
type: llm
weight: 1
---

The answer shows an `mcpServers` entry for the user to add (it doesn't claim to have edited the file). Its `command` is accio given as a full path (such as `/Users/<name>/.local/bin/accio` or `/opt/homebrew/bin/accio`) or with a clear note to use the full path from `command -v accio`. Its `args` are, in this order: `research`, `--no-mask`, `--`, then the server command (`npx`, bare or as a full path, then `-y`, `@modelcontextprotocol/server-brave-search`). `--no-mask` anywhere other than right after `research` fails. It also fails if the entry has an `env` block containing BRAVE_API_KEY with a value or a placeholder for the value, tells the user to paste the key into the config or the chat, or suggests a command that shows the value.
