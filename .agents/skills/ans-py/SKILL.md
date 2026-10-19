---
name: ans-py
description: House rules for the custom mock DNS servers of the BIND 9 system tests (`ansN/ans.py` on `isctest.asyncserver`), each with the commit that applied it, and how to verify a server rewrite with ans_diff. Use whenever you create, edit, review or port an `ans.py`, a shared `<test>_ans.py`, or code under `bin/tests/system/isctest/asyncserver/`.
---

# Custom servers (`ans.py`) in the BIND 9 system tests

How the framework works is documented elsewhere and not repeated here:

- [Mock a misbehaving server](../../../bin/tests/system/README.md#mock-a-misbehaving-server)
  in the system test README is the reference: zone data, handlers and
  matchers, response actions, DNSSEC, control commands, shared code.
- [Set up zones in bootstrap()](../../../bin/tests/system/COOKBOOK.md#set-up-zones-in-bootstrap)
  in the system test cookbook shows how a test provisions a signed zone
  and keys for an `ansN`.
- The framework's own tests under
  `bin/tests/system/isctest/asyncserver/tests/` show each feature in
  isolation, and the existing servers are the best reference for how
  the features combine; the README says how to grep for them.

A non-trivial change to an `ans.py` is best reviewed by someone from QA.

Servers are referred to as `<test>/ansN`: `filters/ans6` is
`bin/tests/system/filters/ans6/ans.py`.

## Structure of a server

An `ansN/ans.py` is laid out top to bottom as:

1. The license header shared by all Python files in the tree.
2. Imports: standard library, `dns.*`, `isctest.*` and the framework
   (`isctest.asyncserver` and its `handlers`, `matchers`, `actions` and
   `commands` submodules).
3. Module constants: the names, addresses and other values the test is
   about.
4. Record builders: small functions returning a `dns.rrset.RRset`, so
   that handler bodies read as data.
5. Handlers: one class per behavior, with a `matcher` declaring the
   queries it takes and either the fixed parts of a
   `StaticResponseHandler` or a `get_responses()` generator.
6. `main()`: construct the server, install the handlers (and control
   commands, if any) and call `run()`, under the usual
   `if __name__ == "__main__":` guard.

Additionally, the server may define:

- a state object that handlers share;
- matchers of its own, `Matcher` subclasses for criteria the library
  lacks;
- control commands, the `ControlCommand` subclasses the test steers
  the server with.

Nothing runs at import time except the constants' definitions and the
call to `main()` from the guard: no server, handler or record is built
at module level.

Zone files in `ansN/zones/` and keys in `ansN/keys/` are the server's
data; the runner starts and stops the server with the test and keeps
its log in `ansN/ans.run`.  Code that several servers of a test share
lives in the test directory itself, in `<test>/<test>_ans.py` beside
the `ansN/` directories, and each server imports it relatively:
`from ..<test>_ans import ...`.

## Checking a server

Run the lint jobs CI runs (the quick checks in `.gitlab-ci.yml`), from
the repository root:

```sh
black $(git ls-files '*.py')
pylint $(git ls-files '*.py')
ruff check
```

## Verifying a rewrite with ans_diff

A rewritten server passes its test whether or not it still sends the
same packets.  `ans_diff.py` (https://gitlab.isc.org/stepan/ans_diff.py,
`main` at `9ae9e89` as of 2026-10-19) is the equivalence check: it
builds two revisions of BIND, runs the system test on each with
`tshark` capturing, and compares the DNS messages exchanged with the
server.  `compare` runs the test on both revisions; `replay` runs it on
the reference only and replays the captured queries to both servers,
which is the mode to use when the set of queries the resolver sends
differs from run to run, for example because of server selection.
`capture` runs the test and keeps the PCAPs without comparing, printing a
`wireshark` command per capture that is filtered to the server's traffic;
given the same revision twice, it is the quick way to see what a new
server exchanges with the resolver.  `ans_diff.py <subcommand> -h`
documents the options; what the help does not say:

- The tool never fetches, so `origin/main` is whatever its clone last
  saw; `--merge-base` compares against the merge base of the two
  revisions.
- Scope the run with `-k` to the modules that use the server.  The
  wiring is often indirect, through a forwarder or a delegation in an
  `nsN` config, so grep for the server's address, not its name.
- A server whose fixture generates keys needs `--ignore-dnssec-data`,
  a `ControllableAsyncDnsServer` needs `--ignore-control-domain`, and
  a replay needs `--packet-order none`; order differences under
  `relaxed` come from parallel queries pairing up differently.
- Splitting one server into several breaks the comparison, because the
  reference has no server at the new address.  Build a scaffolding
  reference: branch from the candidate, so the test wiring is
  identical, and put the old server's code into both the old and the
  new `ansN` directories.

Report a run with the tool revision, the exact command, one line per
non-default option saying why it is there, and the verdict.  When the
result is not clean, say what differs, packet by packet when they are
few, and why that is equivalence rather than regression.

## Verifying a test against the unpatched build

A passing test proves only that the fixed build passes it.  A test
exists to fail on the bug it catches, and a rewritten server can stop
provoking that failure without the test going red.  Find the fix a test
function was written for (the merge request that added it, or the
history of the test) and take it out of the source: by a revert, or by
hand where a revert does not apply or is not enough.  Rebuild and run
the test: that function must fail for the reason the issue describes,
such as a wrong answer from `named` caught by an assertion, or a crash.
After a rewrite it must still fail for the same reason.

## Updating this guide

Where a rule here and the tree on `main` disagree, the guide may be
stale: report the disagreement rather than silently following either.

An excerpt quotes the tree at the commit it cites, so it keeps matching
its citation after the code moves on; what goes stale is the example.
A change to the framework (`bin/tests/system/isctest/asyncserver/`) or
to a server quoted here updates the guide in the same merge request:

- A renamed or changed framework API is renamed or reworded in the
  rule text, and the examples that use it are re-cited from the commit
  that made the change, showing the code after it.
- An example whose server no longer shows the rule is replaced by one
  that does, or dropped.
- A rule the change makes wrong is reworded or removed.  A practice the
  change introduces gets a rule of its own: applied across the tree
  first, then documented with the commit that applied it, placed where
  it fits from general to specific.

`git grep` over `.agents/skills/ans-py/` for the old names finds what
to update.  A merge request cites its own commits by SHA and refreshes
them after its final rebase.

## Rules

Each rule is stated first and then shown under "Examples": excerpts
headed `# <path>:<lines> before <commit>` and `at <commit>` around the
commit that applied the rule, `as of <commit>` for code quoted as it
stood at a commit that did not change it, and `(synthetic)` where no
code in the tree shows it.  "Negative examples" show code the rule does
not cover, which stays as it is.
