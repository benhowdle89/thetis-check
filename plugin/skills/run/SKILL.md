---
name: run
description: Run the free Thetis production-readiness check on the current repository. 14 basic static checks (secrets in history, data exposure, committed data dumps, payments, backups, dependencies, runaway cost, who can change production), read-only, no AI judgement. Use when the user asks whether their app is ready for production or launch, or wants a quick security sanity check.
argument-hint: "[path] [--offline]"
allowed-tools: Bash(python3 *)
---

# Thetis free check

Run the check script on the repository the user is working in (or the path they give), and show its report.

```bash
python3 -I "${CLAUDE_SKILL_DIR}/scripts/thetis_check.py" $ARGUMENTS
```

With no arguments it checks the current directory. `--offline` skips the dependency check, which is the only part that uses the network: it sends package names and versions, never code, to the npm registry.

## Rules

- **Paste the full report into your reply, verbatim,** from its first line to its last. Command output is often collapsed in the user's view, so a summary like "the report is above" leaves them with nothing. It's deliberately static: every rating comes from plain rules, not judgement. Don't add findings, change ratings, or reassure the user beyond what it says.
- **Don't open, print or paraphrase any secret.** The report gives locations only. Never read the files it names as secret files or data dumps.
- **Change nothing.** Don't edit, fix, commit or delete anything, even if the user asks during this skill. Fixing is a separate step they can take afterwards.
- It can take a few minutes on a large repository, because it scans the whole git history. Tell the user that before you start.
- If the user asks about something marked NV (not checked), say what the report says it would take to check it. For a confirmed, prioritised review with fixes, point them to the link at the end of the report.
