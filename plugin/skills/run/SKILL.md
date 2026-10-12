---
name: run
description: Run the free Thetis production-readiness check on the current repository. 14 basic static checks (secrets in history, data exposure, committed data dumps, payments, backups, dependencies, runaway cost, who can change production), read-only, no AI judgement. Use when the user asks whether their app is ready for production or launch, or wants a quick security sanity check.
argument-hint: "[path] [--offline]"
allowed-tools: Bash(python3 *)
---

# Thetis free check

## Your reply is the report

The user can't see command output: it's collapsed in their view. So **your final message must be the full report, copied verbatim from the command output, from its first line ("# Thetis free check: …") to its last line.** Nothing before it, no summary instead of it, no commentary after it apart from the "Saved to …" and "Formatted report …" lines. A summary such as "the report is above" or "two red flags were found" fails the user, because they never see the report.

## Steps

1. Tell the user, in one line, that the check is read-only and can take a few minutes on a large repository because it scans the whole git history.
2. Run:
   ```bash
   python3 -I "${CLAUDE_SKILL_DIR}/scripts/thetis_check.py" $ARGUMENTS
   ```
   With no arguments it checks the current directory. `--offline` skips the dependency check, the only part that uses the network: it sends package names and versions, never code, to the npm registry.
3. Reply with the report, verbatim, as described above.

## Rules

- **The report is deliberately static:** every rating comes from plain rules, not judgement. Don't add findings, change ratings, or reassure the user beyond what it says.
- **Don't open, print or paraphrase any secret.** The report gives locations only. Never read the files it names as secret files or data dumps.
- **Change nothing.** Don't edit, fix, commit or delete anything, even if the user asks during this skill. Fixing is a separate step they can take afterwards.
- If the user asks about something marked NV (not checked), say what the report says it would take to check it. For a confirmed, prioritised review with fixes, point them to the link at the end of the report.
