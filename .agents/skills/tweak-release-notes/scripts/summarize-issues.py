#!/usr/bin/env python3
"""Summarize issue JSON dumps: close-status and version-affecting labels.

This is the deterministic *parsing* half of the close-status / substance
checks. The *fetching* half is a network operation: pull each issue's JSON
with the `gitlab` CLI (anonymous access works for public issues):

    gitlab --server-url https://gitlab.isc.org --skip-login -o json \
        project-issue get --project-id isc-projects/bind9 --iid <N> \
        > <dir>/<N>.json

then run this over that directory.

Usage:
    scripts/summarize-issues.py <dir-of-issue-json>

Flags any issue that is NOT closed (the close-status check) and prints the
"Affects vX" labels (input to the substance review: does a released version
carry the bug?). A non-closed issue is usually one of:
  * omission  -> closed via a non-main / cross-project (e.g. private fork)
                 branch, so auto-close on public main never fired; suggest
                 the maintainer close it.
  * ongoing   -> the MR only referenced the issue (no "Closes"); leave open.
"""

# The hyphenated file name is intentional: these are CLI helpers, not
# importable modules.
# pylint: disable=invalid-name
import glob
import json
import os
import sys


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: summarize-issues.py <dir-of-issue-json>")
    d = sys.argv[1]
    files = sorted(glob.glob(os.path.join(d, "*.json")))
    rows = []
    for f in files:
        if "discussion" in os.path.basename(f):
            continue
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
        except (ValueError, OSError) as exc:
            print(f"# warning: skipping {f}: {exc}", file=sys.stderr)
            continue
        if "iid" not in data:
            print(f"# warning: skipping {f}: no 'iid' key", file=sys.stderr)
            continue
        labels = data.get("labels", [])
        rows.append(
            (
                data["iid"],
                data.get("state", "?"),
                [l for l in labels if l.lower().startswith("affects")] or ["(none)"],
                data.get("title", "")[:50],
            )
        )
    rows.sort()
    not_closed = [r for r in rows if r[1] != "closed"]
    print(
        f"# issues: {len(rows)}   closed: {sum(1 for r in rows if r[1]=='closed')}"
        f"   NOT closed: {len(not_closed)}\n"
    )
    for iid, state, affects, title in rows:
        flag = "  <<< NOT CLOSED" if state != "closed" else ""
        print(f"#{iid}  {state:8} affects={','.join(affects):40} {title}{flag}")
    if not_closed:
        print(
            "\n# NOT CLOSED — reason out each: omission (suggest the"
            " maintainer close it) vs ongoing (leave open)."
        )


if __name__ == "__main__":
    main()
