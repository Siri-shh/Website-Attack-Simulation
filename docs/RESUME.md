# Resume this implementation

This repository is the recovery record. Keep the whole `new_project` directory, including `.git`, when changing accounts or machines. A new account must have access to these local files. Account switching alone does not transfer files to another computer. Runtime `data/` and keys are ignored by Git and must be preserved separately if retaining existing encrypted records.

## Copyable prompt for a new session

> Continue this project from its local repository. Read AGENTS.md, docs/RESUME.md, docs/implementation/PROGRESS.md, docs/implementation/DECISIONS.md, the referenced spec, and the referenced plan. Inspect Git status/history before editing. Resume the first incomplete task at its recorded phase; do not recreate completed work. Use gpt-6-luna for the designated mechanical tasks and gpt-6.1-sol for reasoning, complex tasks, debugging, and reviews. Always explicitly set model and effort. The controller runs all shell/test/Git commands; workers do not. Preserve the separate storage/admin websites, cryptographic evidence and actual saved timings on the storage website, deterministic rules, and manual IP blocks. Honor any pending plan-review gate recorded in PROGRESS. Preserve local milestone commits and checkpoint tags.

## Controller recovery commands (PowerShell)

Run from the repository directory. These are read-only; run them before dispatching an agent.

```powershell
git status --short
git branch --show-current
git log -12 --oneline --decorate
git tag --list 'checkpoint/*'
Get-Content -LiteralPath 'docs/implementation/PROGRESS.md'
Get-Content -LiteralPath 'docs/implementation/DECISIONS.md'
```

1. Check the ledger's plan identity and approval state. AWAITING_PLAN_REVIEW means the next action is review, not implementation.
2. Confirm completed milestones have their named tags and task reports. Trust actual file contents and checks over chat claims.
3. For an interrupted task, read its report and diff. Keep partial work and resume its next recorded phase. Old agent IDs are optional; dispatch a fresh worker with the saved task packet and current files if needed.
4. If files changed after the last recorded verification, rerun that task's checks. If a prior red test exists, do not delete implemented code merely to recreate a red phase; record recovered state and run verification.
5. Recreate `.venv` if it is absent, using the controller commands from the plan. Prefer `requirements-lock.txt` if it exists. Recheck available models and capture dependencies; do not silently substitute models.
6. Continue dependencies in task order. A tag that already exists is not recreated or overwritten. Missing checkpoint documentation is reconciled from Git history and actual evidence before advancing.

## Interruption between checkpoints

Before token exhaustion, the controller stops dispatching new tasks, collects available reports, and writes PROGRESS with the current phase and next exact action. Stop active file writers before making a recovery commit. Do not mark incomplete code as passing.

To save partial work, stage only the actual task files and durable documentation (replace `<owned-file>` with explicit paths):

```powershell
git diff --check
git add -- <owned-file> docs/implementation/PROGRESS.md docs/implementation/DECISIONS.md docs/implementation/reports/TNN.md docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --stat
git commit -m 'wip(TNN): save partial task for resumption'
```

The literal placeholders are a procedure template, not commands to execute unchanged. No milestone tag is created for a partial task. If a commit is unavailable, saved files and the updated ledger still identify the recovery point; report that state.

Local checkpoint tags are restore/reference points, not instructions to reset the current checkout. To inspect old work, use `git show checkpoint/m3-storage:path/to/file`; use a separate inspection checkout if needed, never destroy the unfinished current task.

## Dependency-free fallback

The plan, task contracts, ledger, and reports are plain local Markdown. If a new account lacks the Superpowers plugin, follow those artifacts directly; do not stall solely because account-specific skill paths changed. If it lacks the requested model or repository files, state that concrete missing prerequisite and preserve progress.
