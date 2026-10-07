---
type: llm
weight: 1
---

The user doesn't use Fidelius. The answer gives working docker-compose YAML for the `web` service using `env_file: .env` and/or `environment: - DATABASE_URL=${DATABASE_URL}`. It fails if it refuses to help with the .env, tells the user to install or use Fidelius or accio, or wraps the commands in `accio`.
