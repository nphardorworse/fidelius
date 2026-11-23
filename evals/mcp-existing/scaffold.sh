#!/bin/bash
# A fake Claude Desktop config in the eval workspace, so a run that reads it never touches the real one. The token is made up.
set -e
mkdir -p claude-desktop
cat > claude-desktop/claude_desktop_config.json <<'JSON'
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_fakeTokenForThisEvalOnly000000000000"}
    }
  }
}
JSON
