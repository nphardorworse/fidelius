---
type: llm
weight: 1
---

The answer shows an `mcpServers` entry whose `command` is accio, given as a full path (such as `/Users/<name>/.local/bin/accio`) or with a clear note to use the full path from `command -v accio`, and whose `args` start with `research`, include `--no-mask` and `--`, then the server command (`npx` given as a full path or with the same note, then `-y`, `@modelcontextprotocol/server-brave-search`). It fails if the entry has an `env` block containing BRAVE_API_KEY with a value or a placeholder for the value, tells the user to paste the key into the config or the chat, or suggests a command that shows the value.
