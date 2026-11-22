---
type: llm
weight: 1
---

The answer gives a `claude mcp add` command whose server command is `accio myapp --` followed by the command that starts GitHub's MCP server (for example `docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server`). The order matters: `myapp` comes right after `accio`, then `--`, then the server command. Adding `--no-mask` anywhere fails. A bare `-e GITHUB_PERSONAL_ACCESS_TOKEN` passed to docker, with no value, is fine because docker reads it from accio's environment. It also fails if it puts the token value in the command or a config file (for example `-e GITHUB_PERSONAL_ACCESS_TOKEN=...` on `claude mcp add`, or an `env` block with a value), tells the user to export the token in their shell, asks the user to paste the token, or suggests a command that shows the value.
