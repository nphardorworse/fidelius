---
name: fidelius
description: Use API keys and other secrets from the Fidelius Mac app through the accio command, without reading .env files or printing values. Use when a command needs credentials or environment variables, when a .env file comes up, or when the user mentions Fidelius or accio.
---

# Secrets (Fidelius)

Secrets live in the Fidelius app, grouped by project. Use them through the `accio` command. Never search files for secrets.

- See which projects exist: `accio list`. `shared` is loaded into every project.
- See which variables a project has (names only): `accio list <project> --json`
- Run a command with a project's secrets: `accio <project> <command> [args...]`
- Fail early if something is missing: `accio <project> --require NAME1,NAME2 <command>`
- Use a value inside a one-off command: `accio <project> sh -c 'curl -H "Authorization: Bearer $TOKEN" https://...'`
- File secrets such as `.p8` keys arrive as a path to a temporary file, deleted when the command ends.
- Move a project's .env into Fidelius: `accio import` in the project's folder (or `accio import <project> <file>`). It opens Fidelius's Import preview and saves nothing until the user clicks Import, so ask them to review it there. Never read the .env yourself. Afterwards, suggest deleting the .env: it still holds the values in plain text.
- Most tools don't need a .env: run them with `accio <project> <command>`, or put accio in package.json scripts (`"dev": "accio <project> next dev"`).
- Make a `.env.example` with `accio export --example` in the project's folder. `accio export` (real values) opens Fidelius for the user to approve. Never read or print a .env that holds real values.

Rules:
- Never print, echo, cat or log secret values. Reference them as `$NAME` inside the command only.
- Output from accio is masked on a best-effort basis; that is not permission to print values. If your environment isn't recognized, set FIDELIUS_MASK=1 on accio commands.
- If a variable is missing, tell the user which one and which project, and ask them to add it in Fidelius. If it's in a .env, offer `accio import`.
