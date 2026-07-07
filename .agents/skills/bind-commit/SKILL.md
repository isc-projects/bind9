---
name: bind-commit
description: The full commit workflow for BIND 9 repositories — pre-commit clang-format sequence, message shape and 72-column wrapping, trailer rules (Assisted-by and the forbidden ones), amend/fixup discipline, and the never-push boundary. Use EVERY time you are about to create, amend, reword, or fix up a commit in any BIND 9 checkout.
---

# Committing to BIND 9 — the full checklist

## Pre-commit formatting (C files)

1. `git add <files>`
2. `git-clang-format HEAD` — the hyphenated binary. `git clang-format`
   (with a space) invokes a nonexistent git subcommand and fails. It
   operates on STAGED files only.
3. `git add` any reformatted files, then commit.

Only format C lines you wrote or edited yourself. If the working-tree
diff was authored by the user (their editor, their patch), do NOT run
clang-format over it — it is not your code to reformat.

## Message shape

- ≤3 paragraphs; a single short paragraph is usually enough. Focus on
  WHY — the reviewer can read the diff. Never narrate the diff or
  enumerate per-function before/after behavior ("Gosh the commit
  message is so long and chatty").
- Plain subject, no `new:`/`fix:`/`dev:`/`doc:` prefix — those appear
  only on GitLab-generated MR-merge commits. Real branch-commit style:
  `git log --no-merges --first-parent`.
- Hard-wrap the body at ~72 columns. `git commit -m` does NOT wrap: a
  long paragraph becomes one unwrapped line that sticks out
  immediately. Write the message pre-wrapped to a file and use
  `git commit -F <file>`, or pass each physical line as its own `-m`.

## Trailers

- `Assisted-by: <tool>:<model-id>` (model id from the runtime
  environment, e.g. `claude-fable-5`) ONLY when LLM wrote the
  load-bearing code/test/config content of the commit. NOT for:
  rewording a message, squashing fixups, review-only advice, or a
  comment/doc block added around a user-authored fix — a comment is
  prose, not the fix; do not rationalize "the comment was AI" to keep
  the trailer.
- After the model id, list specialized analysis tools actually used
  (coccinelle, clang-tidy, AFL, Coverity, fuzzers) — never trivial
  tooling (git, compilers, meson, clang-format, black, ruff).
- NEVER, in any repo:
  - `Co-Authored-By: ...` or any AI co-author line;
  - `Signed-off-by:` from the agent (it cannot certify the DCO);
  - `Closes #N` / `Fixes #N` / `Refs #N` — issue refs go in the MR
    description; the branch name already encodes the issue number;

## Amending

- HEAD, polish-only (typo, message tightening, whitespace): plain
  `--amend`; keep the original author (git's default).
- HEAD, implementation replaced by a different approach:
  `--amend --reset-author` (or explicit `--author=`) — attribution
  follows whoever wrote the NEW code, not whoever wrote the discarded
  version. When in doubt about amending someone else's commit, ask
  first. The Assisted-by question is independent — re-derive it from
  who authored the new content.
- NOT HEAD: NEVER rebuild the branch with `git reset --hard <older>` +
  cherry-pick (this once collided with the user's concurrent rebase and
  trashed the branch). Instead add a fixup commit on top:
  - content (and message): `git commit --fixup=amend:<hash>`
  - message only: `git commit --fixup=reword:<hash>` — it opens an
    editor and ignores `-m`; supply the wrapped message via
    `GIT_EDITOR='cp /path/to/msg.txt'`
  - content only, keep message: `git commit --fixup=<hash>`

  Then STOP and hand `git rebase -i --autosquash <base>` to the user —
  never run the rebase yourself.
- Before ANY history operation run `git status`; if a rebase or
  cherry-pick is in progress, do not touch the branch.

## The boundary

Commit locally only. Never `git push` (any variant), never
`gh pr create` / `glab mr create`. When the work is finished, hand the
MR title/description over as text (see the bind-mr-description skill)
— do not offer to push or open the MR.
