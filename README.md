# Thetis free check

A free production-readiness check for apps built with AI coding tools, as a Claude Code plugin. It runs 14 basic checks on your repository: leaked keys in git history, data other users could see, committed database dumps, payment webhooks, backups, vulnerable libraries, runaway costs, and who (or what) can change production.

- **Static:** plain scripts, no AI judgement. The same repo gives the same report.
- **Read-only:** it changes nothing in your repository. The report is saved to `~/.thetis-check/reports/`.
- **Private:** your code never leaves your machine. The dependency check sends package names and versions (not code) to the npm registry; `--offline` skips it.

## Install

In Claude Code:

```
/plugin marketplace add benhowdle89/thetis-check
/plugin install thetis-check@thetis
/thetis-check:run
```

Or run the script directly: `python3 plugin/skills/run/scripts/thetis_check.py /path/to/repo`

## Ratings

**R** needs fixing · **A** weak spot · **OK** nothing found by this basic check · **NV** not checked (needs a person or your dashboards) · **—** doesn't apply

"OK" never means safe. It means this basic check found nothing. For a full review, where a person confirms each finding and you get fixes you only pay for when their tests pass, see [thetis.benhowdle.im](https://thetis.benhowdle.im).

## Requirements

Claude Code, python3 and git. Optional: npm (for check 12) and [gitleaks](https://github.com/gitleaks/gitleaks), which gives a more thorough history scan for check 01.
