# Thetis free check

A free production-readiness check for apps built with AI coding tools. It's a plugin for [Claude Code](https://claude.com/claude-code), Anthropic's coding agent. It runs 14 basic checks on your repository: leaked keys in git history, data other users could see, committed database dumps, payment webhooks, backups, vulnerable libraries, runaway costs, and who (or what) can change production.

- **Static:** plain scripts, no AI judgement. The same repo gives the same report.
- **Read-only:** it changes nothing in your repository. The report is saved to `~/.thetis-check/reports/`.
- **Private:** your code never leaves your machine. The dependency check sends package names and versions (not code) to the npm registry; `--offline` skips it.

## Install

From any terminal:

```sh
claude plugin marketplace add benhowdle89/thetis-check
claude plugin install thetis-check@thetis
```

(In the Claude Code terminal app you can type the same as `/plugin marketplace add benhowdle89/thetis-check` and `/plugin install thetis-check@thetis`. `/plugin` isn't available in the VS Code extension, but the terminal commands work for it too.)

## Run

In Claude Code, in your app's folder:

```
/thetis-check:run
```

Not using Claude Code? Run the script directly:

```sh
git clone https://github.com/benhowdle89/thetis-check
python3 thetis-check/plugin/skills/run/scripts/thetis_check.py /path/to/your/app
```

## Ratings

**R** needs fixing · **A** weak spot · **OK** nothing found by this basic check · **NV** not checked (needs a person or your dashboards) · **—** doesn't apply

"OK" never means safe. It means this basic check found nothing. For a full review, where Ben runs the Thetis review engine, checks every finding himself, and you get fixes you only pay for when their tests pass, see [thetis.benhowdle.im](https://thetis.benhowdle.im).

## Requirements

Claude Code, python3 and git. Optional: npm (for check 12) and [gitleaks](https://github.com/gitleaks/gitleaks), which gives a more thorough history scan for check 01.
