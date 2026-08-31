---
name: tweak-release-notes
description: Review and refine ISC BIND 9 release notes for a new version — audit audience/action tags against the actual change substance, verify every covered issue is closed, and rewrite the auto-generated notes into the project's established prior-art style with correct Sphinx markup, verifying the docs still build. Use when preparing or tweaking BIND 9 release notes (doc/notes/notes-*.rst), reviewing a "prepare documentation"/release branch, producing the "Tweak and reword release notes" commit, or when the user mentions release notes, changelog/notes audience tags, or release-note markup.
---

# Tweak release notes (ISC BIND 9)

Refine the auto-generated release notes for a new BIND 9 version into the
project's reviewed style, after checking that the generated content is correct
and complete. **Notes only** — the changelog is never hand-edited.

## Golden rule

**Recent tags are the source of truth.** This process evolves; when any
convention below is unclear or seems to conflict with what you see, mirror the
most recent released `doc/notes/notes-9.*.rst` files. Consistency — in git
style and in release-note style, content, and markup — is the whole goal.
Stick to existing conventions unless the maintainer asks otherwise.

## Prerequisites

- **`gitlab` (python-gitlab CLI)** — issue reads use anonymous access:
  `gitlab --server-url https://gitlab.isc.org --skip-login -o json
  project-issue get --project-id isc-projects/bind9 --iid <N>`. No token
  needed for public issues.
- **`meson`/`sphinx-build`** — the docs build gate runs directly, no wrapper:
  `meson setup build && meson compile -C build arm` (add `-Ddoc=enabled` to
  setup if it doesn't auto-detect `sphinx-build`).
- The generated `doc/changelog/changelog-<ver>.rst` and
  `doc/notes/notes-<ver>.rst` already exist (committed by "Generate changelog"
  and "Prepare release notes").

## Workflow

Work top to bottom. Details for every step: **[REFERENCE.md](REFERENCE.md)**.
Helper scripts (pure-local git/text + JSON parsing) are in `scripts/`.
The whole workflow operates on a single release branch/checkout — one
`<ver>` at a time.

**Where the work pauses:** the flags produced by steps 3 and 4 need
maintainer decisions, but do not block on them — carry on with steps 5–7
for everything unflagged and present the flags together with the result.
Edits that follow from flag decisions land afterwards as fixups.

1. **Scope the cycle.** Range = the most recent `Set up version for BIND
   9.X.Y` commit `..HEAD`. List merges + their `action:audience` tags:
   `scripts/cycle-merges.py`. (Action/audience taxonomy: REFERENCE.md.)

2. **Audit audience→notes mapping (light checkmark).** This is script-
   generated and rarely wrong: confirm notes-entry count == usr/pkg merge
   count and nothing usr/pkg is missing. Don't over-invest here.

3. **Substance review — the main event.** For every merge, judge whether the
   `action` (sec/new/rem/chg/fix) AND `audience` (usr/pkg/dev/…) match what
   the change actually does — not the diff's size. Read the MR/issue when in
   doubt. **Flag mismatches for the maintainer; do not silently re-tag.** Use
   the triage heuristics in REFERENCE.md. When the maintainer agrees a note
   should move section (e.g. a crash mis-tagged `chg` → belongs in Bug Fixes,
   or a `sec` with no CVE → Bug Fixes minus attribution — examples of past
   maintainer decisions, not standing rules; always flag first), reflect it
   **in the notes only**. The changelog is never edited — it is generated
   from the git log of the already-merged (frozen) MRs — so notes and
   changelog simply differ for this release, which is expected.

4. **Issue close-status check.** Derive the full covered-issue set
   (`scripts/issue-refs.py <ver>`), fetch each via gitlab CLI,
   then `scripts/summarize-issues.py <dir>`. Every covered issue should be
   **closed**. For any that isn't, reason: *omission* (closed via a non-main /
   private-fork branch so auto-close never fired → suggest the maintainer
   close it) vs *ongoing* (MR only referenced it, no `Closes` → leave open).
   Flag, don't fix silently.

5. **Refine the notes (style + markup).** Rewrite into prior-art style: add
   Sphinx roles to everything linkable, render the rest per prior art, fix
   typos, normalize phrasing, place/section entries correctly. Full rules and
   the markup decision table: REFERENCE.md. **When unsure, grep recent notes.**

6. **Verify the docs build.** A required gate after any notes change. Use the
   meson compile; the gate treats Sphinx warnings as errors, so every role
   target must resolve.

7. **Commit.** `Tweak and reword release notes` (verbatim subject, no body) +
   `Assisted-by` trailer; follow-ups as `--fixup`; finish with the standard
   DROP-revert of the changelog. Exact conventions: REFERENCE.md.
