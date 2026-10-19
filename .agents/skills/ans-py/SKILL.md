---
name: ans-py
description: House rules for the custom mock DNS servers of the BIND 9 system tests (`ansN/ans.py` on `isctest.asyncserver`), each with the commit that applied it. Use whenever you create, edit, review or port an `ans.py`, a shared `<test>_ans.py`, or code under `bin/tests/system/isctest/asyncserver/`.
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
