---
type: llm
weight: 1
---

The answer tells the user to add GITHUB_PERSONAL_ACCESS_TOKEN to the Fidelius project myapp (in the Fidelius app, not by pasting it into the chat), then to change the server's entry so `command` is accio's full path and `args` are `myapp`, `--no-mask`, `--`, then the original server command and its arguments, and to remove the token from the `env` block. It may suggest restarting Claude Desktop and changing the token at GitHub if it may have leaked. It fails if it asks the user to paste the config or the token into the chat, or tells the user to keep the token in the `env` block.
