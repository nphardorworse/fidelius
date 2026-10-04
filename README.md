# Fidelius

A Mac app for developer API keys. Keys live in your Keychain, grouped by project, and `accio` runs a command with a project's keys as environment variables. You don't need `.env` files, and AI coding agents can run commands with your keys without reading them, as long as they follow their instructions.

```bash
accio my-app npm run dev
accio my-app fastlane deliver
```

Website and download: [fidelius.blisslabs.dev](https://fidelius.blisslabs.dev/)

## Install

```bash
brew install --cask nphardorworse/tap/fidelius
```

Or download it from the website. Then open Fidelius and choose Setup > Install accio Command. macOS 15 or later.

## What this repo is

The app itself isn't open source. This repo is for:

- **Issues.** Bug reports and feature requests for the app and `accio`.
- **The agent skill.** [`skills/fidelius/SKILL.md`](skills/fidelius/SKILL.md) tells an agent how to use your keys through `accio`. Fidelius can write the same rules into Claude Code's, Codex's and Gemini CLI's global instructions for you (Setup > Add to My Agents Automatically…). The skill is for other agents, or if you'd rather install it as a skill: `npx skills add nphardorworse/fidelius`.

## How it works with agents

- When you choose Setup > Add to My Agents Automatically…, Fidelius adds a short section to `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md` and `~/.gemini/GEMINI.md` (for the agents you have), and shows you the change first. It tells the agent to run commands through `accio` and never to read or print a value.
- Key files such as `.p8` and `.pem` reach the command as a path to a temporary file, deleted when the command ends.
- When Claude Code or Codex runs `accio` and a key shows up in the output, accio replaces it with `<concealed by fidelius: NAME>` and says it did. This is best effort: it catches the exact value and its common encodings (base64, hex, URL and JSON escaping), for values of 6 characters or more, when the output goes to a pipe or a file, which is how agents read it. You can turn it off per key (Hide in agent output). Other agents get it when they set `FIDELIUS_MASK=1`, which the instructions tell them to do.

## What it doesn't protect against

An agent that follows its instructions never sees a value. An agent that decides to misbehave can still get one:

- Running a command with `accio` doesn't ask for Touch ID. Touch ID guards Reveal and Copy in the app, but any program running as you can run `accio`, agents included. Treat it like shell access to your keys.
- Masking can be switched off (`--no-mask`), and it doesn't catch a value that was changed (reversed, split, compressed), a value a command writes to a file and reads back, or output that goes straight to a terminal.
- Keys are readable once the Mac has been unlocked after a restart, so `accio` keeps working while the screen is locked.

Masking is a second line for accidents, like a test printing a key. Your agent's own permission settings are what stop a rogue command.

What Fidelius changes is where the keys sit. In normal use they're not in `.env` files, shell history or a plain text file in your home folder, where any agent can read them by accident. (You can still export a `.env` for a tool that insists on one. Fidelius asks for Touch ID first.)

## Where keys go

- Your keys stay in your Keychain. With iCloud Keychain on, they sync end to end encrypted to your other Macs; with it off, they stay on this Mac. Fidelius has no server and no account.
- The app makes two kinds of network request: the license check with Polar, and Sparkle's update check. No analytics, no crash reporting.
- Backups are off until you turn them on, and are encrypted with a password only you know.

## Reporting a security problem

Please don't open a public issue. Use [private vulnerability reporting](https://github.com/nphardorworse/fidelius/security/advisories/new) instead. See [SECURITY.md](SECURITY.md).

## License

The skill and the files in this repo are MIT licensed.
