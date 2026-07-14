---
name: bind-mr-description
description: Drafting BIND 9 merge-request titles and descriptions — they feed the generated release notes, so the audience is system administrators. Use whenever writing or reviewing an MR title/description, when a change "needs a release note", or when tempted to touch doc/notes/.
---

# BIND 9 MR titles & descriptions

The MR title + description ARE the release note — ISC's release tooling
generates `doc/notes/` entries from merged MRs. Audience: system
administrators, not engineers.

## Security framing: bug vs vulnerability

Local-filesystem misbehavior is a BUG, not a vulnerability. BIND treats
the local filesystem as trusted: no "privilege escalation", "local
attacker", "exploit", "vulnerability", or CVE/severity language for
symlink-following, local TOCTOU, or service-account issues. Describe it
operationally ("X followed symlinks and could overwrite the wrong
file"). Reserve security framing for remote or protocol surfaces:
network input, DNS message parsing, configuration from an untrusted
publisher, signed-zone integrity. Defensive code (lstat/O_NOFOLLOW,
mkstemp) remains the right fix — only the framing changes.

## Title

Short (under ~70 chars), leading with the user-visible impact (crash,
wrong answers, resource exhaustion, new capability).

## Description

- One short paragraph (typically 2–4 sentences), single flow: the
  operational problem, then the fix. No section headings, no bullet
  lists, no restating of the commit message.
- Describe the trigger in operational terms — what the admin configures
  or does, what they observe. No function/struct/variable names, no
  programming jargon (TOCTOU, NULL dereference, use-after-free...).
- Don't list individual changes; summarize the combined effect.
  Test-only or developer-only options get at most a brief mention at
  the end.
- Don't add `Closes #NNNN`.
- Scale to the change: a one-line fix gets ~3 sentences, not a
  structured template.

**Internal-only exception:** for refactors with no operator-visible
impact the audience is developers — naming internal functions is fine —
but the title and description stay just as terse.

## Hard rules

- NO `Assisted-by:` in MR titles or descriptions — that trailer belongs
  on commits; in release-note material it is noise for sysadmins.
- NEVER create or edit files under `doc/notes/` — those are generated
  from merged MRs. A branch without a `doc/notes/` change is not
  missing anything; do not flag it in reviews. "Needs a release note"
  means: write a good MR title and description.
- Hand the finished title/description to the user as text; never open
  the MR yourself (see the bind-commit skill's boundary).
