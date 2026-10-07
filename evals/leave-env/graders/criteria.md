---
type: llm
weight: 1
---

The answer tells the user to run `accio import` in the project folder (or `accio import <project> .env`), to review the keys in Fidelius's Import preview and click Import, and only after that to delete the .env, because it still holds the values in plain text. It also explains how to run commands afterwards with `accio <project> <command>`. It fails if it asks the user to paste the .env contents into the chat or suggests copying the values by hand.
