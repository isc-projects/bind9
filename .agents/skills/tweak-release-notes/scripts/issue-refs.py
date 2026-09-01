#!/usr/bin/env python3
"""Derive the complete set of issues "covered by" the release.

Sources:
  1. Every :gl:`#NNNN` in the generated changelog and notes files for this
     version (authoritative for usr/pkg + dev entries).
  2. Every issue closed/fixed by a cycle merge body (catches test/ci/doc/nil
     merges that close an issue but produce no changelog entry).

Noise such as "PKCS#11" or a diff line "port=53" is excluded by requiring a
close keyword directly before a "#N" ref for body refs (GitLab's default
closing pattern, as in the dangerfile) and the :gl: role for doc refs.

Usage:
    scripts/issue-refs.py <version>            # e.g. 9.21.23
    scripts/issue-refs.py <version> <boundary> # explicit cycle boundary ref

Prints the union, and notes which refs come only from merge bodies (i.e. not
represented in the changelog/notes — usually test/ci issues).
"""

# The hyphenated file name is intentional: these are CLI helpers, not
# importable modules.
# pylint: disable=invalid-name
import re
import subprocess
import sys

GL_RE = re.compile(r":gl:`#(\d+)`")
# Mirror the dangerfile's ISSUE_CLOSING_REGEX (GitLab's default closing
# pattern): a close keyword followed by one or more "#N" refs, where the
# "#" starts the ref — so "fixes PKCS#11 support" does not match.
ISSUE_REF = (
    r"(?:(?:isc-projects/bind9)?#"
    r"|https://gitlab\.isc\.org/isc-projects/bind9/-/issues/)\d+"
)
CLOSE_RE = re.compile(
    r"\b(?:clos(?:e[sd]?|ing)|fix(?:e[sd]|ing)?|resolv(?:e[sd]?|ing)"
    r"|implement(?:s|ed|ing)?):? +"
    r"(?:(?:issues? +)?" + ISSUE_REF + r"(?: *,? +and +| *,? *)?)+",
    re.I,
)
REF_NUM_RE = re.compile(r"(?:#|issues/)(\d+)")


def git(*args):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout


def read_doc(path):
    """Read a doc file's content even if it has been reverted out of HEAD by
    the DROP changelog-revert: try HEAD, then the worktree, then the most
    recent commit that still has the blob."""
    try:
        return git("show", f"HEAD:{path}")
    except subprocess.CalledProcessError:
        pass
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        pass
    for sha in git("log", "--format=%H", "--", path).split():
        try:
            return git("show", f"{sha}:{path}")
        except subprocess.CalledProcessError:
            continue  # e.g. the DROP commit that deleted it
    print(f"# note: {path} not found in history", file=sys.stderr)
    return ""


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: issue-refs.py <version> [<boundary-ref>]")
    version = sys.argv[1]
    if len(sys.argv) > 2:
        boundary = sys.argv[2]
    else:
        boundary = git(
            "log",
            "--first-parent",
            "--grep",
            "Set up version for BIND",
            "-1",
            "--format=%H",
        ).strip()
        if not boundary:
            sys.exit(
                "could not find a 'Set up version for BIND' commit; pass a boundary ref"
            )

    doc_refs = set()
    for path in (
        f"doc/changelog/changelog-{version}.rst",
        f"doc/notes/notes-{version}.rst",
    ):
        doc_refs |= {int(n) for n in GL_RE.findall(read_doc(path))}

    body_refs = set()
    shas = git(
        "log", "--merges", "--first-parent", f"{boundary}..HEAD", "--format=%H"
    ).split()
    for sha in shas:
        body = git("show", "-s", "--format=%b", sha)
        for m in CLOSE_RE.finditer(body):
            body_refs |= {int(n) for n in REF_NUM_RE.findall(m.group(0))}

    union = sorted(doc_refs | body_refs)
    only_body = sorted(body_refs - doc_refs)
    print("# all issues covered (union):")
    print(" ".join(f"#{n}" for n in union))
    print(
        f"\n# count: {len(union)}   from docs: {len(doc_refs)}   from bodies: {len(body_refs)}"
    )
    if only_body:
        print("\n# only in merge bodies (no changelog/notes entry — usually test/ci):")
        print(" ".join(f"#{n}" for n in only_body))


if __name__ == "__main__":
    main()
