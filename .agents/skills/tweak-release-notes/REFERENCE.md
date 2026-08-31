# Release-notes reference (ISC BIND 9)

Detailed conventions for the [tweak-release-notes](SKILL.md) workflow. When
any rule here is unclear or seems stale, **the most recent released
`doc/notes/notes-9.*.rst` files win** (find them with `ls -v` — plain `ls`
sorts 9.21.9 after 9.21.24) — grep them and mirror what they do.

**No silent truncation.** When paging long output (`head`, `tail`), make
sure the ranges join up to cover all of it, and reconcile against the
scripts' printed counts: every merge `cycle-merges.py` lists gets a
substance judgment, and the issue count `summarize-issues.py` parses must
equal the set `issue-refs.py` derived.

---

## 1. Action / audience taxonomy

The changelog and release notes are generated from the **MR title** (and
description), not from commit messages. The title is
`[BRANCH][CVE-…] ACTION: AUDIENCE: short description`.

| ACTION | Notes/changelog section |
| ------ | ----------------------- |
| `sec`  | Security Fixes          |
| `new`  | New Features            |
| `rem`  | Removed Features        |
| `chg`  | Feature Changes         |
| `fix`  | Bug Fixes               |

| AUDIENCE | Release note | Changelog |
| -------- | :----------: | :-------: |
| `usr` (users)      | yes | yes |
| `pkg` (packagers)  | yes | yes |
| `dev` (developers) | no  | yes |
| `test` (testers)   | no  | no  |
| `doc` (docs)       | no  | no  |
| `ci` (infra)       | no  | no  |
| `nil` (none)       | no  | no  |

So a **release note** is generated iff audience is `usr` or `pkg`. Section is
chosen by ACTION. Notes-file section order seen in prior art: Security Fixes,
New Features, Removed Features, Feature Changes, Bug Fixes — include only
sections that have entries.

**Cycle boundary:** the most recent first-parent commit whose subject matches
`Set up version for BIND 9.X.Y` (the version bump opening the cycle). Range is
that commit `..HEAD`. `git log --merges --first-parent` over that range lists
the cycle's MRs; the one `Merge tag 'vX'` back-merge is not an MR (skip it).

---

## 2. Substance review — the main event

The audience→section mapping is script-generated and almost never wrong, so
audit it only as a checkmark (notes count == usr/pkg count; nothing usr/pkg
missing). **Spend the effort judging whether the ACTION and AUDIENCE match the
change's substance** — what a user actually observes, not the diff's size.

Two kinds of mismatch to look for:

- **Action-substance** — e.g. a `chg` when there are no user-visible changes -
  should probably be classified as `fix` instead, or not using `rem` when a
  feature was removed. Alternately, not surfacing user-visible changes as `chg`.
  An internal API/struct change does **not** make a user-facing bug fix into a
  `chg`; the tag classifies user-visible nature, not internal footprint.
- **Audience-substance** — e.g. a `dev` fix whose issue is `Security`-labeled
  and affects a *released* version, shipping with no note; or a `dev` change
  that alters user-visible CLI/behavior.

### Triage heuristics (whether a change deserves a note)

- **Dev-branch-only vs stable-affecting.** A bug affecting only the current
  development branch (e.g. 9.21) is handled with more leeway and often stays
  `dev` even if user-facing-ish. The same class of bug that *also* affects a
  stable branch (e.g. 9.20) is far more likely to warrant `usr` + a note.
  Check the issue's `Affects vX` labels.
- **Developer decision is respected.** If devs deliberately left it `dev`,
  that stands.
- **Reporter origin.** Internal (ISC staff) or CI/sanitizer findings with no
  significant consequence usually get no note. Historically, external
  (non-ISC) user-reported issues were likelier to get a note — but that is
  shifting under the volume of LLM-reported issues, which no longer get the
  same treatment.
- **User/interface changes** generally get a note — *except* when merely
  loosening/relaxing a condition (and/or main-only): OK to skip.
- **Main-only optimizations**: OK to skip.
- **Implementation details** which are unlikely to be visible to sysadmins:
  OK to skip.

### Flag, don't decide

Surface every mismatch with evidence as a flag-for-decision; the maintainer
owns the call (and may relay it to dev). When the maintainer agrees, reflect a
section move / attribution change **in the notes only**.

**The changelog is never edited.** It is generated purely from the git log of
the already-merged MRs, which no longer change at this point. A notes-side
reclassification therefore makes the notes and changelog differ for this
release — that is expected, not a defect to reconcile.

### Label / milestone facts (so you don't chase ghosts)

- The **`Release Notes` GitLab label lives on the MR, not the issue**, and CI
  enforces that it matches the audience. Don't audit issues for it.
- The **"Not released yet" milestone is normal cycle staging** (even `usr` MRs
  carry it) — *not* an embargo hold. Embargoed security fixes go through
  `security-*` branches (auto "Not released yet" + auto backports). A
  `Security`-labeled fix appearing publicly in `main` as `dev` is therefore a
  real audience decision worth questioning, not an embargo artifact.

---

## 3. Issue close-status check

Every issue "covered by" the release should be **closed**. Derive the set with
`scripts/issue-refs.py <ver>` (union of `:gl:` refs in the generated
changelog+notes and `Closes/Fixes #N` in cycle merge bodies; noise like
`PKCS#11` / `port=53` is filtered). Fetch each into one directory with the
`gitlab` CLI (anonymous, no token needed for public issues):

```
gitlab --server-url https://gitlab.isc.org --skip-login -o json \
    project-issue get --project-id isc-projects/bind9 --iid <N> \
    > <dir>/<N>.json
```

then `scripts/summarize-issues.py <dir>`.

For any issue not closed, reason and flag (don't fix silently):

- **Omission** — the closing MR merged via a non-`main` or cross-project
  branch (e.g. the **private fork** for a security fix), so GitLab's auto-close
  on public `main` never fired. → suggest the maintainer close it manually
  (this workflow's GitLab access is anonymous and read-only; you flag, you
  never close).
- **Ongoing** — the MR only *referenced* the issue (no `Closes`/`Fixes`)
  because work remains. → leave it open.

---

## 4. Notes refinement — markup & style

**Prior art is the source of truth.** Before applying any rule, grep recent
notes for how the exact term/construct is already rendered, and match it.

### Sphinx markup decision table

| Thing | Render as | Examples |
| ----- | --------- | -------- |
| named.conf statement/option | `:any:`name``; use `:namedconf:ref:`name`` only when the bare `:any:` target is ambiguous (matches multiple objects) | `:any:`dns64``, `:any:`nxdomain-redirect``, `:any:`tkey-gssapi-keytab``, `:any:`dnssec-policy`` |
| rndc subcommand / CLI option | `:option:`…`` | `:option:`rndc flush``, `:option:`dig -x``, `:option:`named-checkconf -b`` |
| program / man page | `:iscman:`name`` | `:iscman:`named``, `:iscman:`delv``, `:iscman:`dnssec-signzone`` |
| RFC | `:rfc:`NNNN`` | `:rfc:`2535``, `:rfc:`3645` Section 4.1.1` |
| CVE (security only) | `:cve:`YYYY-NNNN`` | summary line of a CVE'd Security Fix |
| GitLab issue / MR | `:gl:`#NNNN`` / `:gl:`!NNNN`` | see ordering below |
| record types in prose | **plain** | A, AAAA, CNAME, DNAME, RRSIG, NS, AXFR, IXFR, meta-types |
| RCODEs | **plain** | SERVFAIL, FORMERR, NOERROR |
| protocols / algorithms | **plain** | TCP, UDP, DoH, Ed25519, Ed448, PKCS#11 |
| filenames, identifiers, struct/func names, counters, internal flags, literal config values | ``literal`` (double backtick) | ``bind9.xsl``, ``MismatchTCP``, ``malloc_trim()``, ``file``, ``unlimited``, ``-C`` |

Notes:
- Record types are **plain** in prose (prior art is ~100:1 plain).
- **Never leave single-backtick** `` `text` `` (the unset default role). Convert
  to a role or a ``literal``. After editing, confirm none survive.
- **Verify every role target resolves** — the build gate is warnings-as-errors.
  Before using `:any:`X``/`:iscman:`X``/`:option:`X``, confirm it's real: grep
  `doc/` for an existing identical use, or for its definition
  (`.. namedconf:statement:: X`, `doc/man/X.*`). If a term is only ever plain
  text and has no definition, keep it a ``literal`` — don't invent a role.
  Avoid ambiguous `:any:` targets (e.g. a bare `file`) that match multiple
  objects → build warning; use a ``literal`` or a domain-qualified role.

### Attribution (security fixes ONLY)

We do **not** attribute non-security fixes. Security Fix entries credit the
reporter, in its own paragraph, matching recent tags:

```
ISC would like to thank <Name> [of|from <Org>] for bringing this
{vulnerability|issue} to our attention. :gl:`#NNNN`
```

When an entry is reclassified out of Security Fixes, **drop the attribution
line** and let `:gl:`#NNNN`` attach to the end of the last body sentence.

### Wording

- Summary line: imperative-verb style (`Fix …`, `Add …`, `Remove …`, `Use …`)
  — but descriptive openers exist in prior art; only rewrite awkward/non-
  imperative summaries. Don't mechanically transform every entry.
- Summary lines DO carry roles (e.g. `Fix :any:`nxdomain-redirect` combined
  with :any:`dns64`.`) — format linkable terms there too, like the body.
- Avoid a sentence-initial lowercase `:iscman:`named`` (renders lowercase
  "named …"); restructure, e.g. "Previously, :iscman:`named` …" or "The
  :iscman:`named` process …".
- Fix obvious typos while you're in the file.
- Intended audience are system administrators. Omit implementation details like
  function names, data structure details etc. Focus on user visible impact.

### Sectioning & entry order

- Move an entry to the correct section if its action/substance was corrected.
  Remove a section that becomes empty (e.g. the lone Security Fix moved
  out → delete the `Security Fixes` header + underline).
- **Entry order is not a strict numeric sort.** The only consistent rule:
  issue entries come before MR-only (`!`) entries within a section. Otherwise
  preserve the generator's order; when inserting a moved entry, place it
  consistent with the order already present (often ascending-by-issue) — verify
  against the file and recent tags.
- **Issue-less entries** (MR only, no `Closes`) cite the MR: append
  `:gl:`!NNNN``. The generator may omit this; prior art includes it.

---

## 5. Build gate

Verifying the docs compile is a **required gate after any notes change**. The
docs are Sphinx; the real CI gate runs `sphinx-build` with **`-W`
(warnings-as-errors)** over `doc/arm` (and `-n` nitpicky depending on
verbosity), so every role target must resolve or the build fails.

Run it directly with meson (sphinx-build underneath):

```
meson setup build   # once; add -Ddoc=enabled if sphinx-build isn't auto-detected
meson compile -C build arm
```

Filter the output for warnings mentioning your notes file.

---

## 6. Commit conventions

For general commit mechanics — message shape, wrapping, trailers,
fixup/amend rules, the never-push boundary — follow the **bind-commit**
skill. Only the release-notes-specific conventions are listed here.

- **The tweak commit:** subject exactly `Tweak and reword release notes`, **no
  body** (this recurring step uses that fixed subject every release — e.g.
  prior `Tweak and reword release notes` commits for 9.21.20/.21/.22).
  Notes-only — the changelog is never in this commit.
- **Never amend the session base** (HEAD at session start, e.g. the "Prepare
  release notes" commit). Add commits on top.
- **Follow-up edits** after you've presented the tweak commit become fixups
  of it (per bind-commit).
- **DROP-revert (standard final step, every release):** revert the generated
  changelog so the GitLab review diff is notes-only, while keeping the
  changelog correct in history.

  ```
  git revert --no-commit <Generate-changelog-sha>
  git commit -F - <<'EOF'
  DROP Revert "Generate changelog for BIND 9.X.Y"

  This reverts commit <full-sha>.

  The generated changelog is correct and kept in place; this revert is
  dropped before merge so the review diff shows only the release-note changes.

  Assisted-by: ...
  EOF
  ```

  The DROP commit sits at the tip and is dropped before merge (which restores
  the changelog). The dangerfile FAILs on `DROP`/`fixup!` subjects — that is
  the intended pre-merge tripwire, not a development-time blocker.
- **Follow-up session with the DROP already at the tip:** add new fixup
  commits on top of the DROP anyway — do not reorder or rewrite history
  yourself. The maintainer's final `git rebase -i --autosquash` squashes the
  fixups into the tweak commit and drops the DROP, so the ordering resolves
  there.

At end of turn, surface any `fixup!`/`DROP` commits present and whether
`git rebase -i --autosquash <base>` applies cleanly; wait for the maintainer
before rewriting history.

---

## 7. Scripts

All pure-local except where noted; run from the repo root.

- `scripts/cycle-merges.py [<boundary>] [<tip>]` — list cycle merges with
  parsed `action:audience` and what each generates; reconciliation counts.
- `scripts/issue-refs.py <ver> [<boundary>]` — derive the complete covered-
  issue set (handles the changelog being reverted out of HEAD by the DROP
  commit); separates doc-referenced from body-only (test/ci) issues.
- `scripts/summarize-issues.py <dir-of-issue-json>` — parse downloaded
  issue JSON: close-status (flags non-closed) and `Affects vX` labels. Fetch
  the JSON first with the `gitlab` CLI (see §3 above).
