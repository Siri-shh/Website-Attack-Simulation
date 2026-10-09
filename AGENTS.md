# Project execution instructions

## Read first

Read `docs/RESUME.md`, then `docs/implementation/PROGRESS.md`. The current specification is `docs/superpowers/specs/2026-10-09-storage-security-design.md`; its implementation plan is `docs/superpowers/plans/2026-10-09-storage-security-plan.md`. User corrections take precedence. Implementation is awaiting plan review until PROGRESS records the user's approval.

Build only in this `new_project` checkout. The sibling `Project` directory is a read-only reference; do not modify its code, data or running services.

## Mandatory delegation

- The controller coordinates work, updates durable progress, and runs every shell command, dependency installation, test, process, and Git operation. Do not delegate command-line or Git tasks.
- Assign bounded, predetermined implementation to `gpt-6-luna` with `reasoning_effort: medium` and `fork_turns: none`.
- Assign architectural decisions, algorithm design, complex implementation, debugging, and independent reviews to `gpt-6.1-sol` with `reasoning_effort: high` and `fork_turns: none`.
- Always specify both model and effort. Do not silently substitute a different model if one is unavailable; record that fact and request the missing model or an explicit alternative.
- Provide each worker its exact task section, relevant contracts, existing owned-file contents, and a report path. Workers may edit assigned files with file-edit tools, but may not run shell/Git commands, install packages, start services, run tests, or spawn helpers. The controller supplies command results.
- Luna must not choose architecture, change interfaces, invent algorithms, or broaden scope. Unspecified behavior or an unexpected failure goes back to a Sol reasoning task; record the resolution in DECISIONS before implementation continues.
- Dispatch at most one implementation writer at a time. Reviewers do not edit files. Bundle review of completed mechanical tasks at milestone gates to conserve tokens; review complex algorithms with Sol before their consumers proceed. The user-requested model routing and controller-only commands override generic plugin defaults.

## Durable history and recovery

- Keep PROGRESS, DECISIONS, per-task reports, plan checkboxes, milestone commits, and checkpoint tags synchronized. Mark a task complete only after the controller's checks and the required Sol review have passed.
- Never delete committed progress or reports, including at project completion. Generic skill scratch ledgers may supplement this record; they cannot replace it.
- Before editing, inspect `git status` and the progress ledger. Preserve partial work. Never rerun completed tasks solely because an agent or conversation disappeared.
- Never use `git reset --hard`, `git clean`, force pushes, blanket recursive deletion, or `git add .` as part of recovery. Stage only explicit milestone files. Keep runtime keys, captures, databases, passwords captured in logs, and virtual environments out of Git.
- A new account needs this repository and its `.git` directory for version history. Do not rely on chat history, account-specific memory, live agent IDs, or installed plugin paths for recovery.

## Context7 documentation

Use Context7 for current library/framework/SDK/API/CLI/cloud documentation, including syntax, setup, configuration, and library-specific debugging, even if familiar. Start with `resolve-library-id` unless an exact `/org/project` ID was supplied. Choose the exact/relevant official match, preferring reputable sources and good coverage. Run `query-docs` for one specific concept per call; separate unrelated concepts. Use the retrieved documentation. Do not fetch docs merely for business logic, general concepts, ordinary refactoring, or code review. If Context7 is unavailable, record the limitation and use official documentation; do not invent API details.
