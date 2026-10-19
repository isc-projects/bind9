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
   `SingleResponseHandler` or a `get_responses()` generator.
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

CI's `mypy` job covers `bin/tests/system/isctest/` only, so a server is
never type-checked there.  Check it by hand, with the package on the
path, and leave no error behind that was not there before:

```sh
MYPYPATH=bin/tests/system mypy --explicit-package-bases --namespace-packages \
    bin/tests/system/<test>/ans<N>/ans.py
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

### Share code through `<test>_ans.py`

When two servers of one test need the same handler or helper, keep one
copy in the test directory's `<test>_ans.py`, parametrized by what
differs, and build each server in its own `ans.py` from it.  The
record builders follow the same rule: in `<test>_ans.py` when more
than one server of the test builds records, in the server otherwise.
Lift what is duplicated, not what merely looks alike: when each
server subclasses a shared base with its own values, the sharing has
already happened, and the subclasses stay in the servers.
What servers of several tests keep rewriting belongs in
`isctest.asyncserver`, in a change of its own that QA reviews.

#### Examples

Two servers that answered the same way with different data, 9cfe470c07.
Before, each server had its own copy with the data inside:

```python
# rpzrecurse/ans5/ans.py:35-42 before 9cfe470c07 (ans6 the same, other values)
class DelayedNsHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.NS)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(ns("foo.child.example.tld.", "ns5.foo."))
        yield DnsResponseSend(qctx.response, delay=3)
```

After, one copy holds the behavior and each server subclasses it
with its own data:

```python
# rpzrecurse/rpzrecurse_ans.py:52-62 at 9cfe470c07
class DelayedNsHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.NS)
    owner: str
    nameserver: str
    delay: float

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(ns(self.owner, self.nameserver))
        yield DnsResponseSend(qctx.response, delay=self.delay)

# rpzrecurse/ans5/ans.py:20-35 at 9cfe470c07
class FooChildDelegationHandler(DelayedNsHandler):
    owner = "foo.child.example.tld."
    nameserver = "ns5.foo."
    delay = 3


class Ns5FooAHandler(AHandler):
    address = ANS5.ip


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        FooChildDelegationHandler(),
        Ns5FooAHandler(),
    )
```

A builder three servers had each written, 58c7826269.  Before, three
definitions that differed only in where the TTL went:

```python
# xfer/ans5/ans.py:154-166 before 58c7826269
def rrset(
    owner: str | dns.name.Name,
    ttl: int,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
) -> dns.rrset.RRset:
    ...

# xfer/ans9/ans.py:35-38 before 58c7826269
def rrset(
    owner: str | dns.name.Name, rdtype: dns.rdatatype.RdataType, rdata: str
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, TTL, dns.rdataclass.IN, rdtype, rdata)

# xfer/ans11/ans.py:38-41 before 58c7826269
def rrset(
    owner: str, ttl: int, rdtype: dns.rdatatype.RdataType, rdata: str
) -> dns.rrset.RRset:
    ...
```

After, one definition imported by all three:

```python
# xfer/xfer_ans.py:18-24 at 58c7826269
def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)

# xfer/ans9/ans.py:31 at 58c7826269
from ..xfer_ans import rrset
```

The same builders in both servers of a test, e4506be134.  Before:

```python
# bailiwick/ans1/ans.py:41-42 before e4506be134
def ns(owner: str | dns.name.Name, target: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, target)

# bailiwick/ans2/ans.py:41-42 before e4506be134
def ns(owner: str | dns.name.Name, target: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, target)
```

After, one copy in the shared module:

```python
# bailiwick/bailiwick_ans.py:43-44 at e4506be134
def ns(owner: str | dns.name.Name, target: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, target)

# bailiwick/ans2/ans.py:18 at e4506be134
from ..bailiwick_ans import ResponseSpoofer, a, cname, dname, ns, spoofing_server, txt
```

`reclimit/reclimit_ans.py` as of 35ab0c255f: a stateful base, handlers
parametrized by what each server answers, a control command, and ans2,
ans4 and ans7 built from them.

#### Negative examples

Helpers that agree only in name.  Each of these bakes in its server's
own SOA; a shared one would take every field as a parameter and each
server would wrap it again:

```python
# xfer/ans5/ans.py:155-164 at 58c7826269
def soa(
    serial: int,
    *,
    owner: str = "nil.",
    mname: str = "ns.nil.",
    rname: str = "root.nil.",
) -> dns.rrset.RRset:
    return rrset(
        owner, dns.rdatatype.SOA, f"{mname} {rname} {serial} 300 300 604800 300"
    )

# xfer/ans9/ans.py:34-35 at 58c7826269
def soa(owner: str | dns.name.Name, serial: int) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.SOA, f". . {serial} 0 0 0 0")

# xfer/ans11/ans.py:40-46 at 58c7826269
def soa(serial: int) -> dns.rrset.RRset:
    return rrset(
        ZONE,
        dns.rdatatype.SOA,
        f"{NS_NAME} admin.{ZONE} {serial} 3600 900 604800 86400",
        ttl=TTL,
    )
```

Four servers subclassing one base with their own values; the shared
part already lives in `srtt_ans.py`, and these stay where they are:

```python
# srtt/ans2/ans.py:20-22 at d6d8e53629
class UndelayedHandler(DelayedQnameRangeHandler):
    max_qname = 99
    delay = 0.0

# srtt/ans3/ans.py:20-22 at d6d8e53629
class Delay30msHandler(DelayedQnameRangeHandler):
    max_qname = 199
    delay = 0.03
```

### A server shows a few behaviors and does not keep growing

One `ansN` is one misbehavior or one small family of them, so that
the file reads as the reproducer it is.  A new reproducer usually
gets a new `ansN` with its own zone data rather than a handler
appended to a server that happens to answer for the right zone:
`ansN` instances are cheap, and a server that keeps accumulating
unrelated handlers stops being readable and makes every addition a
question of install order.  A handler that belongs to the family the
server already shows goes into that server.

`resolver/ans2`, `resolver/ans3` and `serve_stale/ans2` are the long
servers of the tree.  They get no further handlers: a new reproducer
for those tests gets a new `ansN`, and splitting them is a merge
request of its own.

#### Examples

Two reproducers in one server, split, a417bade7f and 6a4ba15807.
Before, `ans1` served the `f025.test` and the `f055.test` attack,
which have nothing in common but the server:

```python
# dnssec_nsec3/ans1/ans.py:16-21 before a417bade7f
def main() -> None:
    keys = common.load_keys()
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handler(f025.F025Handler(keys))
    server.install_response_handler(f055.F055Handler(keys))
    server.run()
```

After, `ans1` keeps the `f025.test` attack and `f055.test` gets `ans3`
of its own:

```python
# dnssec_nsec3/ans1/ans.py:62-65 at 6a4ba15807
def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(AncestorWildcardNsec3Handler())
    server.run()

# dnssec_nsec3/ans3/ans.py:89-96 at 6a4ba15807
def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        ControlAHandler(),
        AttackAHandler(),
        AttackDsHandler(),
    )
    server.run()
```

A split moves a delegation: the `nsN` zone files and configs that
pointed at the old server point at the new address, and the
comparison needs the scaffolding reference from
[Verifying a rewrite with ans_diff](#verifying-a-rewrite-with-ans_diff),
because the reference revision has no server at that address.

A server that is not to be made longer but split, one `ansN` per
family of names it answers for:

```python
# resolver/ans3/ans.py:217-248 at a54bd67584
    server.install_response_handlers(
        ApexNSHandler(),
        AttackDnameHandler(),
        BadCnameHandler(),
        ...
        WwwGoodDnameHandler(),
        WwwHandler(),
    )

    server.install_response_handlers(FallbackHandler())
```

### Dispatch with matchers, not with if-else in `get_responses()`

Every `if` inside `get_responses()` is suspect.  A branch on anything
the matcher could have decided, the query's type, name or protocol, a
label of the name, an EDNS option, what the zone holds for the name,
or how many queries came before, is dispatch, and dispatch is the
matcher's job: each branch becomes its own handler with the criterion
in its `matcher`, installed before the general one so that
first-match-wins routes to it, and a branch that only passed the
prepared response through is dropped and falls through to it.  What
stays inside `get_responses()` is the shaping of the responses the
handler sends.

A criterion the library lacks is a `Matcher` local to the server:
`match(qctx)` and a `__str__` for the log, its state on itself, nothing
written to `qctx`.  A criterion several servers need goes into
`matchers.py` instead.  Every handler builds its own matcher: handlers
that match the same names share the list of names, never the matcher
object, because a matcher may keep state from its last match.

#### Examples

A protocol branch, c369c61b0c.  Before, the handler decided inside:

```python
# dispatch/ans4/ans.py:23-30 before c369c61b0c
class DropUdpHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend | ResponseDrop, None]:
        if qctx.protocol == DnsProtocol.UDP:
            yield ResponseDrop()
        else:
            yield DnsResponseSend(qctx.response)
```

After, the matcher decides, the TCP case that only passed the
prepared response through falls through to the server, and what is
left is the framework's own `IgnoreAllQueries`, scoped to UDP:

```python
# dispatch/ans4/ans.py:17-18 at c369c61b0c
class DropUdpHandler(IgnoreAllQueries):
    matcher = Protocol(DnsProtocol.UDP)
```

A type branch in a fallback, 09dfef781d.  Before, one handler
answering SOA in one section and everything else in another:

```python
# cookie/cookie_ans.py:172-181 before 09dfef781d
class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        if qctx.qtype == dns.rdatatype.SOA:
            qctx.response.answer.append(soa(qctx))
        else:
            qctx.response.authority.append(soa(qctx))
        yield DnsResponseSend(qctx.response)
```

After, the SOA case is a handler of its own, installed ahead of the
general one so that first-match-wins routes to it:

```python
# cookie/cookie_ans.py:190-198 at 09dfef781d
class FallbackSoaHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.SOA)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        qctx.response.answer.append(soa(qctx))
        yield DnsResponseSend(qctx.response)

# cookie/cookie_ans.py:201-207 at 09dfef781d
class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        qctx.response.authority.append(soa(qctx))
        yield DnsResponseSend(qctx.response)
```

```python
# cookie/cookie_ans.py:223-224 at 09dfef781d
    server.install_response_handlers(FallbackSoaHandler())
    server.install_response_handlers(FallbackHandler())
```

A type test guarding the whole body, fa6e8c994a.  Before:

```python
# zero/ans5/ans.py:35-52 before fa6e8c994a
class IncrementARecordHandler(ResponseHandler):
    """
    To test the TTL=0 behavior, increment the IPv4 address by one every
    time we get queried.
    """

    def __init__(self):
        self._ip_address = ipaddress.ip_address("192.0.2.0")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.A:
            a_rrset = rrset(qctx.qname, dns.rdatatype.A, str(self._ip_address), ttl=0)
            qctx.response.answer.append(a_rrset)
            self._ip_address += 1

        yield DnsResponseSend(qctx.response)
```

After, the type is the matcher and the body is the answer:

```python
# zero/ans5/ans.py:36-53 at fa6e8c994a
class IncrementARecordHandler(ResponseHandler):
    """
    To test the TTL=0 behavior, increment the IPv4 address by one every
    time we get queried.
    """

    matcher = Qtype(dns.rdatatype.A)

    def __init__(self):
        self._ip_address = ipaddress.ip_address("192.0.2.0")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        a_rrset = rrset(qctx.qname, dns.rdatatype.A, str(self._ip_address), ttl=0)
        qctx.response.answer.append(a_rrset)
        self._ip_address += 1
        yield DnsResponseSend(qctx.response)
```

A name branch, c84e4f2683.  Before, one handler for two names:

```python
# reclimit/reclimit_ans.py:88-102 before c84e4f2683
class CountAndResetHandler(ReclimitHandler):
    matcher = Qname("count.", "reset.")

    async def _get_counted_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if f"{qctx.qname}" == "count.":
            count_rrset = rrset(
                "count.", dns.rdatatype.TXT, f"{self._state.count}", ttl=0
            )
            qctx.response.answer.append(count_rrset)
            yield DnsResponseSend(qctx.response, authoritative=True)
        elif f"{qctx.qname}" == "reset.":
            self._state.reset()
            yield DnsResponseSend(qctx.response, authoritative=False)
```

After, one handler per name, over the same shared state:

```python
# reclimit/reclimit_ans.py:88-106 at c84e4f2683
class CountHandler(ReclimitHandler):
    matcher = Qname("count.")

    async def _get_counted_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        count_rrset = rrset("count.", dns.rdatatype.TXT, f"{self._state.count}", ttl=0)
        qctx.response.answer.append(count_rrset)
        yield DnsResponseSend(qctx.response, authoritative=True)


class ResetHandler(ReclimitHandler):
    matcher = Qname("reset.")

    async def _get_counted_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        self._state.reset()
        yield DnsResponseSend(qctx.response, authoritative=False)

# reclimit/ans4/ans.py:33-40 at c84e4f2683
    server.install_response_handlers(
        CountHandler(state),
        ResetHandler(state),
        DirectExampleHandler(state, 4),
        IndirectExampleOrgHandler(state, 4),
        Ns1ExampleOrgHandler(state),
        FallbackNxdomainHandler(state),
    )
```

A branch on an EDNS option, 3287837aae.  Before, one handler looked for
the cookie itself:

```python
# resend_loop/ans3/ans.py:57-81 before 3287837aae
class ExampleCookieHandler(ResponseHandler):
    matcher = Domain("example.")

    def _get_cookie(self, qctx: QueryContext) -> dns.edns.CookieOption | None:
        ...
```

After, a matcher that keeps the cookie it found picks the BADCOOKIE
handler, and the rest get a declared SERVFAIL:

```python
# resend_loop/ans3/ans.py:57-79 at 3287837aae
class WithCookie(Matcher):
    """
    Match queries carrying an EDNS COOKIE option; the option of the last
    match is kept in `matched_cookie`.
    """

    def __init__(self) -> None:
        ...

# resend_loop/ans3/ans.py:82-97 at 3287837aae
class BadCookieHandler(ResponseHandler):
    """
    Answer a query that carries a client cookie with BADCOOKIE and a server
    cookie, to trigger the resend loop logic.
    """

    matcher = Domain("example.") & WithCookie()

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        cookie = self.matcher.of(WithCookie).matched_cookie
        cookie.server = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        qctx.response.use_edns(options=[cookie])
        qctx.response.set_rcode(dns.rcode.BADCOOKIE)
        yield DnsResponseSend(qctx.response)

# resend_loop/ans3/ans.py:100-102 at 3287837aae
class ExampleServfailHandler(SingleResponseHandler):
    matcher = Domain("example.")
    rcode = dns.rcode.SERVFAIL
```

A branch on a header flag, 1d516f3951.  Before, the handler tested
the CD bit of each NSEC query itself:

```python
# nsec_synthesis/ans1/f004.py:108-121 before 1d516f3951
        elif qctx.qname == self.attacker and qctx.qtype == dns.rdatatype.NSEC:
            if qctx.query.flags & dns.flags.CD:
                ...
            else:
                response.set_rcode(dns.rcode.REFUSED)
        elif qctx.qname == self.victim and qctx.qtype == dns.rdatatype.NSEC:
            if qctx.query.flags & dns.flags.CD:
                ...
            else:
                response.set_rcode(dns.rcode.REFUSED)
```

After, the library's `Flags` is part of each attack handler's matcher,
and the queries without CD fall through to the handler installed after
them:

```python
# nsec_synthesis/ans1/ans.py:29-31 at 1d516f3951
    matcher = (
        Qname("attacker.f004.test.") & Qtype(dns.rdatatype.NSEC) & Flags(dns.flags.CD)
    )

# nsec_synthesis/ans1/ans.py:43-45 at 1d516f3951
    matcher = (
        Qname("victim.f004.test.") & Qtype(dns.rdatatype.NSEC) & Flags(dns.flags.CD)
    )

# nsec_synthesis/ans1/ans.py:60-64 at 1d516f3951
    server.install_response_handlers(
        AttackCoveringNsecHandler(),
        AttackNodataNsecHandler(),
    )
    server.install_response_handlers(RefusedNsecHandler())
```

A branch on how many queries came before, 5a62d06c7d.  Before, the
handler counted:

```python
# digdelv/ans7/ans.py:43-59 before 5a62d06c7d
class SilentThenServfailHandler(ResponseHandler):
    """
    Handler that drops one query and response to the next one with SERVFAIL.
    """

    matcher = Domain("silent-then-servfail.example")
    counter = 0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend | ResponseDrop, None]:
        if self.counter % 2 == 0:
            yield ResponseDrop()
        else:
            qctx.response.set_rcode(dns.rcode.SERVFAIL)
            yield DnsResponseSend(qctx.response, authoritative=False)
        self.counter += 1
```

After, the count is the matcher's, the handler only drops, and the
server's default RCODE answers the rest:

```python
# digdelv/ans7/ans.py:43-60 at 5a62d06c7d
class EverySecond(Matcher):
    """
    Match every second query the given matcher matches, the first one
    included.
    """

    def __init__(self, matcher: Matcher) -> None:
        ...

# digdelv/ans7/ans.py:63-69 at 5a62d06c7d
class SilentEverySecondQueryHandler(IgnoreAllQueries):
    """
    Handler that doesn't respond to every second query, so that the next
    one gets the server's SERVFAIL.
    """

    matcher = EverySecond(Domain("silent-then-servfail.example"))
```

Matchers local to a server: a predicate the library lacks, and a
library predicate given a name and a description:

```python
# reclimit/reclimit_ans.py:176-195 at c84e4f2683
class Ns1Example(Matcher):
    """
    Match queries for ns1.<n>.example.<tld>.
    """

    def __init__(self, tld: str) -> None:
        self.tld = tld.encode()

    def match(self, qctx: QueryContext) -> bool:
        labels = qctx.qname.labels
        return (
            len(labels) == 5
            and labels[3] == self.tld
            and labels[2] == b"example"
            and labels[1].isdigit()
            and labels[0] == b"ns1"
        )

    def __str__(self) -> str:
        return f"QNAME is ns1.<n>.example.{self.tld.decode()}"

# statschannel/ans5/ans.py:38-44 at 7c63549173
class DelayLabel(LabelPredicate):
    """
    Match queries whose leftmost label is the delay in milliseconds.
    """

    def __init__(self) -> None:
        super().__init__(0, bytes.isdigit, "the delay in milliseconds")
```

### One install call per dispatch group

Handlers are tried in the order they are installed, and the first one
whose matcher accepts the query answers it.  Handlers that never match
the same query cannot shadow each other, so their order does not matter:
they go in one `install_response_handlers()` call.  Where one handler
must be tried before another, each group goes in a call of its own, in
the order the groups are tried, so that every call boundary marks an
order that is deliberate.  A call with two or more handlers puts each on
its own line; a single handler stays on the line of the call.  A switch
mapping's sequence cannot be split into calls, so it is listed in
dispatch order.

Within a call, handlers that follow the steps of the test are listed in
that order, so that the server tells the test's story.  Handlers that
tell no story, answering unrelated queries as in a rewritten server that
had grown one handler per reproducer, are sorted alphabetically.  The
handler classes are defined in the order they are installed, a base
class before its subclasses, so that the file reads in dispatch order.

#### Examples

Two groups, the specific one first, e56a73a4ea.  Before:

```python
# fetchlimit/ans4/ans.py:78-80 before e56a73a4ea
    server.install_response_handlers(
        DelayedAHandler(), DelayedAaaaHandler(), AHandler(), AaaaHandler()
    )
```

After:

```python
# fetchlimit/ans4/ans.py:78-85 at e56a73a4ea
    server.install_response_handlers(
        DelayedAHandler(),
        DelayedAaaaHandler(),
    )
    server.install_response_handlers(
        AHandler(),
        AaaaHandler(),
    )
```

Four stages of one server, same commit.  Before:

```python
# dnssec_cname_response/ans2/ans.py:206-221 before e56a73a4ea
def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR, default_aa=True)
    server.install_response_handlers(
        InsecureApexCnameHandler(),
        ExampleMetatypeCnameHandler(),
        NxdomainHandler(EXAMPLE),
        NodataHandler(EXAMPLE),
        SignedZoneHandler(EXAMPLE),
        SecureDsCnameHandler(),
        NxdomainHandler(SECURE),
        NodataHandler(SECURE),
        SignedZoneHandler(SECURE),
        StuffedNxdomainHandler(STUFFED),
        SignedZoneHandler(STUFFED),
    )
    server.run()
```

After:

```python
# dnssec_cname_response/ans2/ans.py:206-227 at e56a73a4ea
def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR, default_aa=True)
    server.install_response_handlers(
        ExampleMetatypeCnameHandler(),
        InsecureApexCnameHandler(),
        SecureDsCnameHandler(),
    )
    server.install_response_handlers(
        NxdomainHandler(EXAMPLE),
        NxdomainHandler(SECURE),
        StuffedNxdomainHandler(STUFFED),
    )
    server.install_response_handlers(
        NodataHandler(EXAMPLE),
        NodataHandler(SECURE),
    )
    server.install_response_handlers(
        SignedZoneHandler(EXAMPLE),
        SignedZoneHandler(SECURE),
        SignedZoneHandler(STUFFED),
    )
    server.run()
```

A call in the order of the test's steps, same commit: the initial SOA
and AXFR, then the refresh SOA, the IXFR truncated over UDP and the
IXFR race over TCP:

```python
# xfer/ans11/ans.py:200-206 at e56a73a4ea
    server.install_response_handlers(
        InitialSoaHandler(progress),
        InitialAxfrHandler(progress),
        RefreshSoaHandler(progress),
        TruncatedIxfrHandler(),
        RaceIxfrHandler(),
    )
```

Handlers that tell no story, alphabetized, same commit: each answers
a name of its own for an unrelated test.  Before:

```python
# digdelv/ans7/ans.py:74-78 before e56a73a4ea
    server.install_response_handlers(
        CloseHandler(),
        SilentHandler(),
        SilentEverySecondQueryHandler(),
    )
```

After:

```python
# digdelv/ans7/ans.py:74-78 at e56a73a4ea
    server.install_response_handlers(
        CloseHandler(),
        SilentEverySecondQueryHandler(),
        SilentHandler(),
    )
```

A switch mapping's sequence in dispatch order, same commit: the EDNS
RCODE handler before the general AXFR handler, and the SOA handler
first, as the transfer starts with it:

```python
# xfer/ans5/ans.py:296-300 as of e56a73a4ea
            "ednsformerr": (
                SignResponses(SoaHandler()),
                SignResponses(AxfrEdnsFormerrHandler()),
                SignResponses(XferAxfrHandler(txt_data="EDNS FORMERR")),
            ),
```

Handlers defined in install order, b5899c314a.  Before, the handler
installed first was defined second:

```python
# dnssec/ans10/ans.py:33 before b5899c314a
class AddRrsigToAHandler(ResponseHandler):

# dnssec/ans10/ans.py:48 before b5899c314a
class AddNsecToTxtHandler(ResponseHandler):

# dnssec/ans10/ans.py:62-65 before b5899c314a
    server.install_response_handlers(
        AddNsecToTxtHandler(),
        AddRrsigToAHandler(),
    )
```

After:

```python
# dnssec/ans10/ans.py:33 at b5899c314a
class AddNsecToTxtHandler(ResponseHandler):

# dnssec/ans10/ans.py:45 at b5899c314a
class AddRrsigToAHandler(ResponseHandler):
```

### `Once` wraps the whole criterion

A handler that answers one query and then leaves the rest to the general
handler does not count in its body: its matcher is `Once(...)` around
the whole criterion, `Once(Qname(...) & Qtype(...))`, and it is
installed before the general handler so that later queries fall through
to it.  `Once` around a part of the criterion means something else: an
inner `Once(Qname(...))` is used up by the first query of that name,
which the outer `& Qtype(...)` may then reject, and the handler is
disarmed without having answered.

#### Examples

The one handler answering once, `filters/ans6/ans.py` as of e56a73a4ea,
and its place in the install order, before the general AAAA handler:

```python
# filters/ans6/ans.py:63-72 as of e56a73a4ea
class NodataOnceHandler(SingleResponseHandler):
    """
    Answer only the first AAAA query, with NODATA, so the DNS64 resolver looks
    up an A record.  If the NODATA expires from the cache before the A answer
    arrives, filter-a re-enters and re-queries AAAA (answered by AaaaHandler),
    triggering the bug.
    """

    matcher = Once(Qname(DNS64_TRIGGER) & Qtype(dns.rdatatype.AAAA))
    authority = [soa()]

# filters/ans6/ans.py:92-100 as of e56a73a4ea
    server.install_response_handlers(
        IgnoreFirstTwoAHandler(),
        NodataOnceHandler(),
    )
    server.install_response_handlers(
        AHandler(),
        AaaaHandler(),
    )
    server.install_response_handlers(FallbackHandler())
```

### Shared state is one object, read by a matcher, advanced in `get_responses()`

State that several handlers of a server share is one plain object,
constructed in `main()` and handed to each of them through the
`__init__()` of one base handler; it is neither a handler nor a
module global.  Prefer a `dataclass` for it, or an `asyncio.Event`
when the only state is that one thing has happened: whatever makes it
happen sets it, and a handler that holds a response until then awaits
it.  A class with a constructor is for state that also knows how its
values are derived or reset.  A handler whose answer depends on the
state does not test it in `get_responses()`: a server-local `Matcher`
reads the state, and each value it tells apart gets a handler of its
own.  A matcher only reads; the state changes in the `get_responses()`
of the handler whose response changes it, or in the control command
the test sends to change it.  A value that never changes after
construction is not state: it is a module constant.

#### Examples

A handler that held the state of a server, e5764f4bfd.  Before:

```python
# reclimit/reclimit_ans.py:44-73 before e5764f4bfd
class ReclimitStateHandler(ResponseHandler):
    """
    Handler for the "count." and "reset." queries that also holds the state
    shared by all the handlers in one server.
    """

    matcher = Qname("count.", "reset.")

    def __init__(self, indirect_send_response_default: bool = True) -> None:
        self._indirect_send_response_default = indirect_send_response_default
        self.count = 0
        self.limit = 0
        self.indirect_send_response = indirect_send_response_default
        super().__init__()

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if f"{qctx.qname}" == "count.":
            self.count += 1
            count_rrset = rrset("count.", dns.rdatatype.TXT, f"{self.count}", ttl=0)
            qctx.response.answer.append(count_rrset)
            yield DnsResponseSend(qctx.response, authoritative=True)
        elif f"{qctx.qname}" == "reset.":
            self.reset()
            yield DnsResponseSend(qctx.response, authoritative=False)

    def reset(self) -> None:
        self.count = 0
        self.indirect_send_response = self._indirect_send_response_default
```

After, a plain object, a class with a constructor because one of its
values starts from another and `reset()` restores them, and the base
handler taking it:

```python
# reclimit/reclimit_ans.py:44-58 at e5764f4bfd
class ReclimitState:
    """
    Query counter, query limit and the referral-or-answer switch shared by
    all the handlers of one server.
    """

    def __init__(self, indirect_send_response_default: bool = True) -> None:
        self._indirect_send_response_default = indirect_send_response_default
        self.count = 0
        self.limit = 0
        self.indirect_send_response = indirect_send_response_default

    def reset(self) -> None:
        self.count = 0
        self.indirect_send_response = self._indirect_send_response_default

# reclimit/reclimit_ans.py:61-71 at e5764f4bfd
class ReclimitHandler(ResponseHandler, abc.ABC):
    """
    Base class for handlers in this test.

    Increments the shared query counter on each query and delegates the actual
    response generation to the `_get_counted_responses()` method.
    """

    def __init__(self, state: ReclimitState) -> None:
        self._state = state
        super().__init__()
```

One phase per handler, read through a matcher and advanced in
`get_responses()`, `xfer/ans11/ans.py` as of 1fe44dda10:

```python
# xfer/ans11/ans.py:86-94 as of 1fe44dda10
@dataclass
class TransferState:
    """
    Flag toggled once the initial AXFR (serial 1) has been served.  The SOA
    handlers read it to advertise serial 1 before the transfer and serial 4
    after it, so the secondary's next refresh switches from AXFR to IXFR.
    """

    initial_axfr_served: bool = False

# xfer/ans11/ans.py:97-109 as of 1fe44dda10
class InitialAxfrServed(Matcher):
    """
    Match once the initial AXFR has been served.
    """

    def __init__(self, progress: TransferState) -> None:
        self._progress = progress

    def match(self, qctx: QueryContext) -> bool:
        return self._progress.initial_axfr_served

    def __str__(self) -> str:
        return "after the initial AXFR"

# xfer/ans11/ans.py:122-127 as of 1fe44dda10
class InitialSoaHandler(TransferHandler, SingleResponseHandler):
    answer = [soa(1)]

    def __init__(self, progress: TransferState) -> None:
        super().__init__(progress)
        self.matcher = Qtype(dns.rdatatype.SOA) & ~InitialAxfrServed(progress)

# xfer/ans11/ans.py:130-135 as of 1fe44dda10
class RefreshSoaHandler(TransferHandler, SingleResponseHandler):
    answer = [soa(4)]

    def __init__(self, progress: TransferState) -> None:
        super().__init__(progress)
        self.matcher = Qtype(dns.rdatatype.SOA) & InitialAxfrServed(progress)

# xfer/ans11/ans.py:138-155 as of 1fe44dda10
class InitialAxfrHandler(TransferHandler, AxfrHandler):
    """
    Serve the initial zone (serial 1) and mark the transfer as done.
    """

    initial_soa = soa(1)
    zone_contents = [
        ns(),
        a(NS_NAME, "127.0.0.1"),
    ]
    final_soa = soa(1)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        self._progress.initial_axfr_served = True
        async for action in super().get_responses(qctx):
            yield action

# xfer/ans11/ans.py:197-207 as of 1fe44dda10
def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    progress = TransferState()
    server.install_response_handlers(
        InitialSoaHandler(progress),
        RefreshSoaHandler(progress),
        InitialAxfrHandler(progress),
        TruncatedIxfrHandler(),
        RaceIxfrHandler(),
    )
    server.run()
```

#### Negative examples

State that one handler alone reads and writes is that handler's own
attribute, `zero/ans5/ans.py` as of e5764f4bfd:

```python
# zero/ans5/ans.py:35-42 as of e5764f4bfd
class IncrementARecordHandler(ResponseHandler):
    """
    To test the TTL=0 behavior, increment the IPv4 address by one every
    time we get queried.
    """

    def __init__(self):
        self._ip_address = ipaddress.ip_address("192.0.2.0")
    ...
```

### `get_responses()` is annotated with what it yields

`get_responses()` is annotated with the action it yields:
`AsyncGenerator[DnsResponseSend, None]` for a handler that sends DNS
messages, the union of what it really yields otherwise.  The base
type, `ResponseAction`, belongs to the abstract method and to a
handler that relays another handler's actions unchanged; a handler
that yields one kind of action does not hide it behind the base type.

#### Examples

A handler annotated with the base type, 65dd953293.  Before:

```python
# digdelv/ans5/ans.py:40-65 before 65dd953293
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        ...
            yield CloseConnection()
        ...
            yield DnsResponseSend(qctx.response)
        ...
            yield DnsResponseSend(qctx.response)
        yield CloseConnection()
```

After, the two actions it yields:

```python
# digdelv/ans5/ans.py:39-64 at 65dd953293
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[CloseConnection | DnsResponseSend, None]:
        ...
            yield CloseConnection()
        ...
            yield DnsResponseSend(qctx.response)
        ...
            yield DnsResponseSend(qctx.response)
        yield CloseConnection()
```

A handler sending raw bytes, `tsig/ans2/ans.py` as of 4e803f2d69:

```python
# tsig/ans2/ans.py:26-33 as of 4e803f2d69
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[BytesResponseSend, None]:
        ...
        yield BytesResponseSend(tc_response.to_wire()[:-1])
```

#### Negative examples

A handler relaying whatever the wrapped handler yields keeps the base
type, `serve_stale/ans9/ans.py` as of 4e803f2d69:

```python
# serve_stale/ans9/ans.py:89-97 as of 4e803f2d69
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        ...
                yield action
```

### Edit the prepared response and yield it

Before a handler runs, the server prepares `qctx.response`: the answer
from the zone data on a server with zone files, an empty message
carrying the server's defaults on one without.  The handler edits that
message and yields it.  The message is rendered only when it is sent, so
every change made before the yield reaches the wire, even one made after
a `to_wire()` call, and nothing is invalidated or re-rendered by hand.

Call `qctx.prepare_new_response()` only when a fresh message is needed:
to replace the prepared answer on a server with zone files, or to start
a second message after the first was yielded.  On a server without zone
files the prepared message is already empty, and a call there as the
handler's first statement discards nothing while reading as if it did.
Build a message by hand, with `dns.message.make_response()` or from
wire, only when the test needs one the prepared response cannot become,
such as an upstream answer relayed as it came back.  `DnsResponseSend`
refuses such a message, since it bypasses the server's RCODE and AA
handling, unless it is sent with `acknowledge_hand_rolled_response=True`.

A TSIG-signed response is the exception: once signed and rendered it
is sent as it is, so a change made after the signing step is lost,
and `authoritative=` on such a response raises for that reason.
Finish the message, the AA bit included, then sign.

#### Examples

A message made by hand, 1fc206556b.  Before:

```python
# qmin/ans2/ans.py:69 before 1fc206556b
    response = dns.message.make_response(qctx.query)
```

After:

```python
# qmin/ans2/ans.py:69 at 1fc206556b
    response = qctx.prepare_new_response(with_zone_data=False)
```

A relayed upstream answer, which the prepared response cannot become,
the framework's `ForwarderHandler`, `isctest/asyncserver/handlers.py`
as of 1ff1a40935:

```python
# isctest/asyncserver/handlers.py:361-363 as of 1ff1a40935
        try:
            message = dns.message.from_wire(response.result(), keyring=False)
            yield DnsResponseSend(message, acknowledge_hand_rolled_response=True)
```

A change after rendering reaches the wire, the package's own test,
`isctest/asyncserver/tests/response_handling/ans1/ans.py` as of
1ff1a40935:

```python
# isctest/asyncserver/tests/response_handling/ans1/ans.py:69-82 as of 1ff1a40935
class RenderedBeforeSendHandler(ResponseHandler):
    """
    Render the response to wire before changing it, as a handler measuring
    its size would; the changes must still reach the client.
    """

    matcher = Qname(f"rendered.{ZONE}")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.to_wire()
        qctx.response.answer.append(txt(qctx.qname, "added after rendering"))
        yield DnsResponseSend(qctx.response, authoritative=False)
```

The needless call on a server without zone files (synthetic).  Before:

```python
# ans2/ans.py, before (synthetic)
class ServfailHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = qctx.prepare_new_response(with_zone_data=False)
        response.set_rcode(dns.rcode.SERVFAIL)
        yield DnsResponseSend(response)
```

After:

```python
# ans2/ans.py, after (synthetic)
class ServfailHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.set_rcode(dns.rcode.SERVFAIL)
        yield DnsResponseSend(qctx.response)
```

A server with zone files whose handler replaces the prepared answer,
`dnssec_cname_response/ans2/ans.py` as of 1ff1a40935:

```python
# dnssec_cname_response/ans2/ans.py:61-72 as of 1ff1a40935
class CnameHandler(ResponseHandler):
    """
    Answer with a CNAME instead of the real records.
    """

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        target = f"cname-target.{qctx.qname.to_text()}"
        qctx.response.answer.append(cname(qctx.qname, target))
        yield DnsResponseSend(qctx.response)
```

A second message after the first was yielded, `xfer/ans11/ans.py` as
of 1ff1a40935:

```python
# xfer/ans11/ans.py:172-194 as of 1ff1a40935
class RaceIxfrHandler(ResponseHandler):
    """
    Reproduce the IXFR->AXFR use-after-free races (GL#5767 and GL#6114).

    Over TCP, send two valid IXFR diffs.  The first starts the apply worker and
    the second remains queued after that worker splices the first chunk.
    Immediately follow them with a SERVFAIL response that makes
    xfrin_recv_done() defer the AXFR retry until the worker finishes.  Cleanup
    then has to detach the queued second chunk before freeing it.
    """

    matcher = Qtype(dns.rdatatype.IXFR) & Protocol(DnsProtocol.TCP)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        for rrset_ in ixfr_diffs():
            qctx.response.answer.append(rrset_)
        yield DnsResponseSend(qctx.response)

        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.set_rcode(dns.rcode.SERVFAIL)
        yield DnsResponseSend(qctx.response)
```

The signature goes on last, in a wrapper, `xfer/ans5/ans.py` as of
1ff1a40935:

```python
# xfer/ans5/ans.py:72-80 as of 1ff1a40935
    def _modify_response(
        self, qctx: QueryContext, response_action: ResponseAction
    ) -> None:
        assert isinstance(
            response_action, DnsResponseSend
        ), "SignResponses can only wrap handlers that yield DnsResponseSend"
        response_action.response.use_tsig(self._key)
        if qctx.protocol == DnsProtocol.TCP:
            self._apply_tsig_context(response_action.response)
```

### A handler that sends one response declares its parts

When a handler sends one response whose parts it can state up front,
state them instead of writing code that assembles them: subclass
`SingleResponseHandler` and set `answer`, `authority`, `additional`,
`rcode`, `authoritative`, `delay` and `edns` as class attributes; there
is no `get_responses()` to write.  A part that comes from the
constructor, or from state the server keeps, is a property that returns
it.

#### Examples

A fixed RCODE, ddc48a04e2.  Before:

```python
# xfer/ans5/ans.py:252-259 before ddc48a04e2
class IxfrNotimpHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.IXFR)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.set_rcode(dns.rcode.NOTIMP)
        yield DnsResponseSend(qctx.response)
```

After:

```python
# xfer/ans5/ans.py:254-256 at ddc48a04e2
class IxfrNotimpHandler(SingleResponseHandler):
    matcher = Qtype(dns.rdatatype.IXFR)
    rcode = dns.rcode.NOTIMP
```

A fixed referral, same commit.  Before:

```python
# statistics/ans4/ans.py:40-50 before ddc48a04e2
class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        name = "below.www.example.com."
        ns_name = f"ns.{name}"
        ns_rrset = rrset(name, dns.rdatatype.NS, ns_name)
        a_rrset = rrset(ns_name, dns.rdatatype.A, NS3.ip)
        qctx.response.authority.append(ns_rrset)
        qctx.response.additional.append(a_rrset)
        yield DnsResponseSend(qctx.response)
```

After:

```python
# statistics/ans4/ans.py:24 at ddc48a04e2
NAME = "below.www.example.com."

# statistics/ans4/ans.py:40-42 at ddc48a04e2
class FallbackHandler(SingleResponseHandler):
    authority = [rrset(NAME, dns.rdatatype.NS, f"ns.{NAME}")]
    additional = [rrset(f"ns.{NAME}", dns.rdatatype.A, NS3.ip)]
```

A part built from what the constructor was given, a property,
`dnssec_cname_response/ans2/ans.py` as of ddc48a04e2:

```python
# dnssec_cname_response/ans2/ans.py:133-147 as of ddc48a04e2
class NxdomainHandler(SingleResponseHandler):
    """
    Answer NXDOMAIN from a signed zone, with its SOA.
    """

    rcode = dns.rcode.NXDOMAIN

    def __init__(self, zone: dns.zone.Zone) -> None:
        self._zone = zone
        assert self._zone.origin
        self.matcher = Domain(self._zone.origin) & NoNameIn(zone)

    @property
    def authority(self) -> Sequence[dns.rrset.RRset]:
        return soa_with_rrsig(self._zone)
```

#### Negative examples

A record owned by the query name is not a part the handler can state
up front, so the handler keeps its `get_responses()`:

```python
# forward/ans6/ans.py:82-88 as of 9d77495155
class NegativeSoaHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.use_edns(None)
        qctx.response.authority.append(soa(qctx.qname))
        yield DnsResponseSend(qctx.response)
```

A handler that keeps the zone data of the prepared response and adds
to it is not a single response from parts either, however fixed the
records it adds: `SingleResponseHandler` starts from an empty
response.

```python
# forward/ans11/ans.py:29-44 as of 9d77495155
class ExtraAnswersHandler(ResponseHandler):
    """
    Answer from zone data, inserting extra RRsets into responses to A queries.
    """

    matcher = Domain("attackSecureDomain.net3.") & Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        parent = self.matcher.of(Domain).domain.parent()
        ns_rrset = rrset(parent, dns.rdatatype.NS, f"local.{parent}")
        qctx.response.answer.append(ns_rrset)
        a_rrset = rrset(f"local.{parent}", dns.rdatatype.A, ANS11.ip)
        qctx.response.additional.append(a_rrset)
        yield DnsResponseSend(qctx.response)
```

### A transfer is declared by its parts

An AXFR is served by an `AxfrHandler` stating `initial_soa`,
`zone_contents` and `final_soa`; an IXFR by a `SingleResponseHandler`
whose `answer` is the diff sequence.  Hand-building the transfer
messages is right only when the test is about the framing itself: a
transfer cut short, a connection closed, an SOA at the wrong place, a
TC bit set.

#### Examples

A transfer stated as its three parts, `nsupdate/ans11/ans.py` as of
79ba163482:

```python
# nsupdate/ans11/ans.py:65-80 as of 79ba163482
class SigAxfrHandler(AxfrHandler):
    """
    Serve an AXFR carrying two legacy SIG (24) rdatas at one owner whose
    body "covered type" fields differ (A, MX); per RFC 3755 SIG has no
    covered-type semantics, so the transferring secondary must store both
    in a single opaque rdataset.
    """

    matcher = Qname(ZONE) & Qtype(dns.rdatatype.AXFR)
    initial_soa = soa()
    zone_contents = [
        rrset(ZONE, dns.rdatatype.NS, NS_NAME),
        rrset(NS_NAME, dns.rdatatype.A, ANS11.ip),
        sig(),
    ]
    final_soa = soa()
```

An IXFR declared as its diff sequence, `ixfr/ans2/ans.py` as of
79ba163482:

```python
# ixfr/ans2/ans.py:91-92 as of 79ba163482
class IxfrHandler(SingleResponseHandler, abc.ABC):
    matcher = Qtype(dns.rdatatype.IXFR)

# ixfr/ans2/ans.py:95-107 as of 79ba163482
class SuccessfulIxfrHandler(IxfrHandler):
    answer = (
        soa(3),
        soa(1),
        a("10.0.0.61", owner="a.nil."),
        txt("initial AXFR"),
        soa(2),
        txt("successful IXFR"),
        a("10.0.1.61", owner="a.nil."),
        soa(2),
        soa(3),
        soa(3),
    )
```

#### Negative examples

A transfer whose framing is what the test drives, cut short or not
answered on command, `digdelv/ans5/ans.py` as of 79ba163482:

```python
# digdelv/ans5/ans.py:40-72 as of 79ba163482
class ErraticAxfrHandler(ResponseHandler):
    allowed_actions = ["no-response", "partial-axfr", "complete-axfr"]

    def __init__(self, actions: list[str]) -> None:
        self.actions = actions
        self.counter = 0
        for action in actions:
            assert action in self.allowed_actions

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[CloseConnection | DnsResponseSend, None]:
        action = self.actions[self.counter % len(self.actions)]
        self.counter += 1

        logging.info("current response action: %s", action)

        if action == "no-response":
            yield CloseConnection()
            return

        soa_rr = rrset(qctx.qname, dns.rdatatype.SOA, ". . 0 0 0 0 300")
        ns_rr = rrset(qctx.qname, dns.rdatatype.NS, ".")

        qctx.response.answer.append(soa_rr)
        qctx.response.answer.append(ns_rr)

        if action == "partial-axfr":
            yield DnsResponseSend(qctx.response)
        elif action == "complete-axfr":
            qctx.response.answer.append(soa_rr)
            yield DnsResponseSend(qctx.response)
        yield CloseConnection()
```

### Build with the library, break the message last

A response, a record or a signature is built with the normal objects:
the prepared `qctx.response` or the query, the dnspython constructors,
`dns.dnssec`, `dns.zone`, `isctest.zone`, and the framework's
`qctx.sign()`, `qctx.get_rrsig()` and `qctx.nsecx`.  Hand-written key
parsing, zone reading, signing, hashing, bitmap or wire building is a
sign that a library call was missed: before keeping such a helper, name
the DNS concept it computes and replace the helper with the library call
for it, which changes no behavior.

Build the valid message or record first and break it as the last step:
the bytes go to `BytesResponseSend` only after the message was built,
and a broken record is the valid RDATA with one field replaced, wrapped
back into an RRset.  Everything not under attack is then right by
construction and readable.

#### Examples

An RRSIG signed by hand, 0bd39806aa.  Before:

```python
# nsec3/ans7/ans.py:138-182 before 0bd39806aa
def sign_rrset(
    private_key,
    key_tag,
    rrset,
    type_covered,
    labels,
    original_ttl,
    expiration,
    inception,
    signer_name,
):
    ...
    sig_rdata = struct.pack("!HBBI", type_covered, algorithm, labels, original_ttl)
    sig_rdata += struct.pack("!II", expiration, inception)
    sig_rdata += struct.pack("!H", key_tag)
    ...
    rrsig_rdata = dns.rdata.from_wire(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        full_rrsig_wire,
        0,
        len(full_rrsig_wire),
        None,
    )
    return rrsig_rdata
```

After, the library signing with the zone's key:

```python
# nsec3/ans7/ans.py:112-128 at 0bd39806aa
    def sign(
        self,
        rrset: dns.rrset.RRset,
        signer_name: dns.name.Name = dns.name.from_text("evil.test."),
    ) -> dns.rdata.Rdata:
        """
        Sign an RRset with the zone's ZSK and return the RRSIG rdata.
        """
        return dns.dnssec.sign(
            rrset,
            self._zsk.private_key,
            signer_name,
            self._zsk.dnskey[0],
            inception=self.RRSIG_INCEPTION,
            expiration=self.RRSIG_EXPIRATION,
            verify=True,
        )
```

Base32 decoded by hand to get at the NSEC3 hashes, same commit.
Before:

```python
# nsec3/ans7/ans.py:109-112 before 0bd39806aa
def b32_to_bytes(b32hex_str):
    """Decode base32hex (RFC 4648) to bytes."""
    padded = b32hex_str.upper() + "=" * ((8 - len(b32hex_str) % 8) % 8)
    return base64.b32hexdecode(padded)
```

After, the zone object holds them decoded:

```python
# nsec3/ans7/ans.py:84-98 at 0bd39806aa
    def _discover_nsec3_targets(
        self, zone_file: str = "../ns6/evil.test.db.signed"
    ) -> None:
        """
        Set the (name, NSEC3) inject and modify targets from the signed zone.
        """
        zone = dns.zone.from_file(zone_file, origin=self.ZONE, relativize=False)
        records = sorted(
            (name, cast(NSEC3, rdata))
            for name, _, rdata in zone.iterate_rdatas(dns.rdatatype.NSEC3)
        )
        assert len(records) >= 2, f"need >= 2 NSEC3 records, found {len(records)}"
        inject, modify, *_ = records
        self._inject_name, self._inject_nsec3 = inject
        self._modify_name, _ = modify
```

A message truncated by one byte after it was built, `tsig/ans2/ans.py`
as of 7dfca66681:

```python
# tsig/ans2/ans.py:20-33 as of 7dfca66681
class TruncatedWithLastByteDroppedHandler(ResponseHandler):
    """
    Return a TC=1 response with the final byte removed to make
    dns_message_parse() return ISC_R_UNEXPECTEDEND.
    """

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[BytesResponseSend, None]:
        tc_response = qctx.query
        tc_response.flags |= dns.flags.QR
        tc_response.flags |= dns.flags.TC
        tc_response.flags |= dns.flags.RA
        yield BytesResponseSend(tc_response.to_wire()[:-1])
```

### DNSSEC comes from the framework, not from the server

A signed zone in `zones/` with its keys in `keys/`, both put there by
the test's `bootstrap()` through `isctest.zone.Zone`, is served the way
`named` serves a signed zone: the prepared response carries the RRSIGs,
the DS records at delegations and the NSEC or NSEC3 proofs.  The fixture
signs the zone before the server starts, and the server never signs it
itself.  Every server of the directory starts for every module: a
module's fixture provisions the zones of the servers that module
queries, and a server it leaves alone starts without zone files and
stays idle.  For anything beyond the zone data, a handler signs a record
with `qctx.sign()`, reads a stored signature with `qctx.get_rrsig()` and
proves non-existence with `qctx.nsecx`.  A server does not read key
files or call `dns.dnssec.sign()` by hand: its keys reach it through
`qctx.keys`, and its signatures come from these calls.

Where the response can come from the zone, take the zone's data and edit
it rather than building it by hand: the prepared response, or the zone's
own records and signatures from `qctx.zone` and `qctx.get_rrsig()`, TTLs
included, with only what the attack needs changed.  A record the zone
does not hold is built and signed with `qctx.sign()`, with a key from
`qctx.keys` when another zone's key must sign it, and `bogus=True` for a
signature that must not verify.  A server whose behavior is the signed
zone plus one wrong thing is a signed zone file and one handler that
edits the prepared response.

#### Examples

The fixture signing the zone for the server,
`dnssec_wildcard/tests_dnssec_wildcard_additional.py` as of 8594ab5b79:

```python
# dnssec_wildcard/tests_dnssec_wildcard_additional.py:41-45 as of 8594ab5b79
def bootstrap():
    zone = isctest.zone.Zone("f043.test.", isctest.template.ANS1, signed=True)
    zone.configure(csk=True)

    return {"trust_anchors": zone.trust_anchors()}
```

A forged wildcard answer built from the zone's own record and its
stored signature, `dnssec_wildcard/ans1/ans.py` as of 8594ab5b79:

```python
# dnssec_wildcard/ans1/ans.py:23-54 as of 8594ab5b79
def append_forged_a_rrset_to_additional(qctx: QueryContext, owner_name: str) -> None:
    # Append a forged wildcard-synthesized record to the response.  The
    # attacker does NOT control the contents of the A record - they have to
    # match the contents of the actual wildcard record present in the zone or
    # else the wildcard RRSIG (see below) won't validate, foiling the attack.
    assert qctx.zone
    wildcard_name = dns.name.from_text("*", origin=qctx.zone.origin)
    wildcard_a_rrset = qctx.zone.get_rrset(wildcard_name, dns.rdatatype.A)
    assert wildcard_a_rrset
    forged_a_rrset = dns.rrset.from_rdata(
        owner_name, wildcard_a_rrset.ttl, *wildcard_a_rrset
    )
    qctx.response.additional.append(forged_a_rrset)

    # Get the RRSIG for the wildcard record from the zone that matched the
    # query.
    wildcard_rrsig = qctx.zone.get_rrset(
        wildcard_name, dns.rdatatype.RRSIG, covers=dns.rdatatype.A
    )
    assert wildcard_rrsig

    # Append the RRSIG for the wildcard record as the signature for the
    # forged A record, making it look as if the A record was synthesized
    # from the wildcard record.
    forged_a_rrsig = dns.rrset.from_rdata(
        owner_name, wildcard_rrsig.ttl, *wildcard_rrsig
    )
    qctx.response.additional.append(forged_a_rrsig)

    # No proof-of-nonexistence is provided for the QNAME and yet a vulnerable
    # resolver validates the forged A record as a secure response synthesized
    # from a wildcard record.

# dnssec_wildcard/ans1/ans.py:67-74 as of 8594ab5b79
class WildcardAdditionalHandler(ResponseHandler):
    matcher = Qname("svc.f043.test.") & Qtype(dns.rdatatype.MX)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        append_forged_a_rrset_to_additional(qctx, "victim.f043.test.")
        yield DnsResponseSend(qctx.response)
```

A server that loaded its own keys and signed by hand, 9ba17f4acc.
Before:

```python
# dnssec_parent_rrsig/ans1/ans.py:55-58 before 9ba17f4acc
def load_keys() -> dict[str, Key]:
    path = Path(__file__).resolve().parent / "keys.json"
    with path.open(encoding="utf-8") as keys_file:
        raw_keys = json.load(keys_file)
    ...

# dnssec_parent_rrsig/ans1/ans.py:82-94 before 9ba17f4acc
def add_signed(
    section: list[dns.rrset.RRset], covered: dns.rrset.RRset, signer: Key
) -> None:
    rrsig = dns.dnssec.sign(
        covered,
        signer.private_key,
        signer.zone,
        signer.dnskey,
        lifetime=86400,
        verify=True,
    )
    section.append(covered)
    section.append(dns.rrset.from_rdata(covered.name, covered.ttl, rrsig))

```

After, a record the zone does not hold, signed with the zone's key,
as of 8594ab5b79:

```python
# dnssec_parent_rrsig/ans1/ans.py:33-47 as of 8594ab5b79
class AncestorAdditionalHandler(ResponseHandler):
    matcher = Qname("q.f044.test.") & Qtype(dns.rdatatype.MX)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        # Append a forged record from the child zone to the response.
        forged_a_rrset = rrset("svc.child.f044.test.", dns.rdatatype.A, "6.6.6.6")
        qctx.response.additional.append(forged_a_rrset)

        # Sign the forged child zone record using the parent zone's key.
        forged_a_rrsig = qctx.sign(forged_a_rrset)
        qctx.response.additional.append(forged_a_rrsig)

        yield DnsResponseSend(qctx.response)
```

A record signed with another zone's key, from a fixture that signs a
parent and its delegated child, `nsec3_impersonation` at
d55c8fd8ab:

```python
# nsec3_impersonation/tests_nsec3_impersonation.py:39-52 at d55c8fd8ab
def bootstrap():
    parent_origin = "tld.test"
    parent_nsec3_hash = dns.dnssec.nsec3_hash(parent_origin, None, 0, 1)

    child_origin = f"{parent_nsec3_hash}.{parent_origin}"

    child = isctest.zone.Zone(child_origin, isctest.template.ANS1, signed=True)
    child.configure(csk=True)

    parent = isctest.zone.Zone(parent_origin, isctest.template.ANS1, signed=True)
    parent.delegations = [child]
    parent.configure(csk=True, sign_params="-3 -")

    return {"trust_anchors": parent.trust_anchors()}

# nsec3_impersonation/ans1/ans.py:50-76 as of 8594ab5b79
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.set_rcode(dns.rcode.NXDOMAIN)

        assert qctx.soa
        qctx.response.authority.append(qctx.soa)
        if soa_rrsig := qctx.get_rrsig(qctx.soa):
            qctx.response.authority.append(soa_rrsig)

        assert qctx.zone
        assert qctx.zone.origin
        parent_apex_hash = dns.dnssec.nsec3_hash(qctx.zone.origin, None, 0, 1)
        child_origin = dns.name.from_text(parent_apex_hash, origin=qctx.zone.origin)
        child_signing_key = qctx.keys[child_origin][0]

        nsec3_rrset = rrset(
            child_origin,
            dns.rdatatype.NSEC3,
            f"1 0 0 - {parent_apex_hash} NS SOA RRSIG DNSKEY NSEC3PARAM",
        )
        nsec3_rrsig = qctx.sign(nsec3_rrset, key=child_signing_key)
        qctx.response.authority.append(nsec3_rrset)
        qctx.response.authority.append(nsec3_rrsig)

        yield DnsResponseSend(qctx.response, authoritative=True)
```

### A server never decides at startup which test it serves

A conditional install keyed on which fixture files exist, or a
handler that disarms itself when its key is missing, is two servers
in one directory, or a fixture that is written for only one of them.
`start.pl` starts every `ansN` of the directory for every module and
fails the test if one does not write `ans.pid` within 90 seconds, so
a server idle for the current module still starts.  Resolve it one
of three ways: every module's fixture generates what every server
needs, each scenario gets a server of its own, or the scenarios get
test directories of their own.

#### Examples

An install keyed on the fixture file of the current module
(synthetic).  Before:

```python
# ans1/ans.py, before (synthetic)
def main() -> None:
    server = AsyncDnsServer()
    if Path("zones/f043.test.db.signed").exists():
        server.install_response_handlers(WildcardAdditionalHandler())
    if Path("zones/f045.test.db.signed").exists():
        server.install_response_handlers(ParentWildcardHandler())
    server.run()
```

After, every handler installed and both modules' zones signed by their
fixtures, `dnssec_wildcard/ans1/ans.py` as of 49fded03e3:

```python
# dnssec_wildcard/ans1/ans.py:77-83 as of 49fded03e3
def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(
        ParentWildcardHandler(),
        WildcardAdditionalHandler(),
    )
    server.run()
```

A handler that disarms itself when the module did not provision its
key, 364d78222a.  Before, `ans1` installed two reproducers, each with
a check like this one, and whichever module ran, one of them did
nothing:

```python
# nsec_synthesis/ans1/f023.py:87-92 before 364d78222a
    def __init__(self, keys: dict[str, Key]) -> None:
        super().__init__()
        self.keys = keys

        if F023_ZONE not in keys:
            return
```

After, `f023.test` has a server of its own and no handler checks for a
key, `nsec_synthesis/ans4/ans.py` as of bf5257bf06:

```python
# nsec_synthesis/ans4/ans.py:22-35 as of bf5257bf06
class AttackChildNsecHandler(AttackNsecHandler):
    """
    An NSEC for a name in the insecure child zone evil.f023.test whose next
    name reaches past target.f023.test in the signed parent.
    """

    matcher = Qname("0.evil.f023.test.") & Qtype(dns.rdatatype.NSEC)
    nsec = "zzz.f023.test. A RRSIG NSEC"


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(AttackChildNsecHandler())
    server.run()
```

### Let the server carry the RCODE and the AA bit

What every handler of a server sets the same way, or what equals the
package's own default, is not set per handler: it goes to the
constructor's `default_rcode` and `default_aa`, and a handler sets
only what makes it differ.

#### Examples

An AA bit set where the server already has it so, 2b97cc9397.  Before:

```python
# fwdfirst/ans2/ans.py:22-27 before 2b97cc9397
class PoisonReferralForwarder(SingleResponseHandler):
    matcher = Domain("fwd.hack.")
    authority = [ns(matcher.domain.parent(), f"ns.{matcher.domain}")]
    additional = [a(f"ns.{matcher.domain}", ANS3.ip)]
    rcode = dns.rcode.NOERROR
    authoritative = False

# statistics/ans4/ans.py:45-48 before 2b97cc9397
def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR, default_aa=False)
    server.install_response_handlers(FooInfoHandler(), FallbackHandler())
    server.run()
```

After:

```python
# fwdfirst/ans2/ans.py:22-26 at 2b97cc9397
class PoisonReferralForwarder(SingleResponseHandler):
    matcher = Domain("fwd.hack.")
    authority = [ns(matcher.domain.parent(), f"ns.{matcher.domain}")]
    additional = [a(f"ns.{matcher.domain}", ANS3.ip)]
    rcode = dns.rcode.NOERROR

# statistics/ans4/ans.py:45-48 at 2b97cc9397
def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(FooInfoHandler(), FallbackHandler())
    server.run()
```

An RCODE set by the one handler that answered, 5a62d06c7d.  Before:

```python
# digdelv/ans7/ans.py:43-59 before 5a62d06c7d
class SilentThenServfailHandler(ResponseHandler):
    """
    Handler that drops one query and response to the next one with SERVFAIL.
    """

    matcher = Domain("silent-then-servfail.example")
    counter = 0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend | ResponseDrop, None]:
        if self.counter % 2 == 0:
            yield ResponseDrop()
        else:
            qctx.response.set_rcode(dns.rcode.SERVFAIL)
            yield DnsResponseSend(qctx.response, authoritative=False)
        self.counter += 1

# digdelv/ans7/ans.py:62-69 before 5a62d06c7d
def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(
        CloseHandler(),
        SilentHandler(),
        SilentThenServfailHandler(),
    )
    server.run()
```

After, the server's default RCODE answers every query the handler
does not drop:

```python
# digdelv/ans7/ans.py:63-69 at 5a62d06c7d
class SilentEverySecondQueryHandler(IgnoreAllQueries):
    """
    Handler that doesn't respond to every second query, so that the next
    one gets the server's SERVFAIL.
    """

    matcher = EverySecond(Domain("silent-then-servfail.example"))

# digdelv/ans7/ans.py:72-79 at 5a62d06c7d
def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.SERVFAIL)
    server.install_response_handlers(
        CloseHandler(),
        SilentHandler(),
        SilentEverySecondQueryHandler(),
    )
    server.run()
```

### A handler's name says what it does

Ideally the name gives a clear idea of what the handler does, so that
the install list and the log read as a list of behaviors.  In a
server that answers for many names, what is matched belongs in the
name as well; in a small server it is clear from the test, and the
behavior alone will do.  A server that reproduces an attack may
instead name each handler after its part in the attack, as `Attack`,
`Control` or `Poisoned` followed by what it answers, so that the
install list narrates the attack the way the test tells it.  Each
docstring then says what its response does.  A CVE number or a GitLab
issue number is not a name: it says where the bug was filed, not what
the server does about it.

A handler class ends with `Handler`, unless a more specific noun says
its role better, as a forwarder or a logger does.  A mixin that
handlers are built from is not a handler and takes no suffix.

#### Examples

Four servers named by the range of names they answer for, d6d8e53629.
Before:

```python
# srtt/ans3/ans.py:20-22 before d6d8e53629
class Foo1ToFoo199Handler(DelayedQnameRangeHandler):
    max_qname = 199
    delay = 0.03
```

After, named by what sets them apart, the delay:

```python
# srtt/ans3/ans.py:20-22 at d6d8e53629
class Delay30msHandler(DelayedQnameRangeHandler):
    max_qname = 199
    delay = 0.03

# srtt/ans2/ans.py:20-22 at d6d8e53629
class UndelayedHandler(DelayedQnameRangeHandler):
    max_qname = 99
    delay = 0.0
```

A handler named by the CVE it reproduces, same commit; the number
stays in the docstring, where the history belongs.  Before:

```python
# chain/ans3/ans.py:63-99 before d6d8e53629
class Cve202125215(ResponseHandler):
    ...
```

After, named by the response, a CNAME at the owner of a DNAME:

```python
# chain/ans3/ans.py:63-99 at d6d8e53629
class CnameToDnameOwnerHandler(ResponseHandler):
    ...
```

Two handlers named "broken", same commit.  Before:

```python
# cyclic_glue/ans5/ans.py:40-55 before d6d8e53629
class BrokenFooHandler(SingleResponseHandler):
    matcher = Qname("a.foo.test.") & Qtype(dns.rdatatype.A)
    ...

# cyclic_glue/ans5/ans.py:58-74 before d6d8e53629
class BrokenBarHandler(SingleResponseHandler):
    matcher = Qname("a.bar.test.") & Qtype(dns.rdatatype.A)
    ...
```

After, named by what is wrong with each referral:

```python
# cyclic_glue/ans5/ans.py:40-55 at d6d8e53629
class FooForeignGlueReferralHandler(SingleResponseHandler):
    matcher = Qname("a.foo.test.") & Qtype(dns.rdatatype.A)
    ...

# cyclic_glue/ans5/ans.py:58-74 at d6d8e53629
class BarForeignNsReferralHandler(SingleResponseHandler):
    matcher = Qname("a.bar.test.") & Qtype(dns.rdatatype.A)
    ...
```

Two handlers without the suffix, same commit.  Before:

```python
# rpzrecurse/ans5/ans.py:23-33 before d6d8e53629
class ReplyA(ResponseHandler):
    ...

# rpzrecurse/ans5/ans.py:36-50 before d6d8e53629
class DelayNs(ResponseHandler):
    ...
```

After:

```python
# rpzrecurse/ans5/ans.py:23-33 at d6d8e53629
class AHandler(ResponseHandler):
    ...

# rpzrecurse/ans5/ans.py:36-50 at d6d8e53629
class DelayedNsHandler(ResponseHandler):
    ...
```

A forwarder named after its target, same commit.  Before:

```python
# pipelined/ans5/ans.py:16-18 before d6d8e53629
class ForwardToNs2(ForwarderHandler):
    target = "10.53.0.2"
    delay = 0.5
```

After, named by what it adds, the delay, with the role as the last word:

```python
# pipelined/ans5/ans.py:16-18 at d6d8e53629
class DelayedForwarder(ForwarderHandler):
    target = "10.53.0.2"
    delay = 0.5
```

#### Negative examples

A name whose last word says the role better than `Handler` would:

```python
# qmin/ans3/ans.py:20-21 as of d6d8e53629
class QueryLogger(QueryLogHandler):
    matcher = Domain("8.2.6.0.1.0.0.2.ip6.arpa.", "a.b.stale.", "zoop.boing.good.")
```

A mixin, and the handler built from it:

```python
# xfer/ans9/ans.py:78-91 as of d6d8e53629
class SerialCounted(ResponseHandler, abc.ABC):
    def __init__(self, serials: SerialCounter) -> None:
        super().__init__()
        self._serials = serials

class SoaHandler(SerialCounted):
    matcher = Qtype(dns.rdatatype.SOA)
    ...
```

### Records come from builders

A server builds its records through helper builders, never through
an inline `dns.rrset.from_text()` that spells the TTL and the class
out at every call.

The least is one generic builder, `rrset(owner, rdtype, rdata,
ttl=...)`, that fixes the class and defaults the TTL.  A record type
the server builds again and again with the same fields gets a builder
of its own on top of it, taking only what varies; a builder used once
is fine too, where the generic call would be long.

A builder is named after the type it returns: `soa()`, `ns()`,
`a()`, not `soa_rrset()`, since the suffix says nothing the return
type does not.  No function in an `ans.py` or `<test>_ans.py` carries
a leading underscore.

At the call site, a per-type builder reads well as an argument,
`append(a(owner, address))`.  A record of a type the server builds
only once may be the generic call itself, in a class attribute as
anywhere else: `zone_contents = [rrset(ZONE, dns.rdatatype.NS,
NS_NAME), ...]`.  In `get_responses()`, a generic call is assigned to
a variable named after the record first, `a_rrset = rrset(...)`, and
the variable is appended.

#### Examples

Inline records replaced by builders, 98b812beaf.  Before, every
record spelled the TTL and the class out:

```python
# bailiwick/ans1/ans.py:27-55 before 98b812beaf
class SiblingNsSpoofer(ResponseSpoofer, mode="sibling-ns"):

    qname = "trigger."

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = qctx.prepare_new_response(with_zone_data=False)

        txt_rrset = dns.rrset.from_text(
            qctx.qname,
            TTL,
            qctx.qclass,
            dns.rdatatype.TXT,
            '"spoofed answer with extra NS"',
        )
        response.answer.append(txt_rrset)

        ns_rrset = dns.rrset.from_text(
            "victim.", TTL, qctx.qclass, dns.rdatatype.NS, "ns.attacker."
        )
        response.authority.append(ns_rrset)

        a_rrset = dns.rrset.from_text(
            "ns.attacker.", TTL, qctx.qclass, dns.rdatatype.A, ATTACKER_IP
        )
        response.additional.append(a_rrset)

        yield DnsResponseSend(response, authoritative=True)
```

After, a builder for each record type the server builds, over the
generic one:

```python
# bailiwick/ans1/ans.py:49-62 at 98b812beaf
class SiblingNsSpoofer(ResponseSpoofer, mode="sibling-ns"):

    qname = "trigger."

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = qctx.prepare_new_response(with_zone_data=False)

        response.answer.append(txt(qctx.qname, "spoofed answer with extra NS"))
        response.authority.append(ns("victim.", "ns.attacker."))
        response.additional.append(a("ns.attacker.", ATTACKER_IP))

        yield DnsResponseSend(response, authoritative=True)

# bailiwick/ans1/ans.py:28-34 at 98b812beaf
def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 3600,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)

# bailiwick/ans1/ans.py:41-42 at 98b812beaf
def ns(owner: str | dns.name.Name, target: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, target)
```

A generic call stays where one record of a type is built, same
commit; it is assigned to a variable named after the record before
the append:

```python
# zero/ans5/ans.py:33-43 before 98b812beaf
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.A:
            rrset = dns.rrset.from_text(
                qctx.qname, 0, qctx.qclass, dns.rdatatype.A, str(self._ip_address)
            )
            qctx.response.answer.append(rrset)
            self._ip_address += 1

        yield DnsResponseSend(qctx.response)
```

```python
# zero/ans5/ans.py:44-52 at 98b812beaf
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.A:
            a_rrset = rrset(qctx.qname, dns.rdatatype.A, str(self._ip_address), ttl=0)
            qctx.response.answer.append(a_rrset)
            self._ip_address += 1

        yield DnsResponseSend(qctx.response)
```

Builders named after the type they return, bc8a0746f2.  Before:

```python
# resolver/resolver_ans.py:45-46 before bc8a0746f2
def soa_rrset(qname: dns.name.Name | str) -> dns.rrset.RRset:
    return rrset(qname, dns.rdatatype.SOA, ". . 0 0 0 0 0")

# chain/ans4/ans.py:106-109 before bc8a0746f2
    @classmethod
    def create_rrset_signature(
        cls, owner: dns.name.Name, rrtype: dns.rdatatype.RdataType
    ) -> dns.rrset.RRset:
```

After:

```python
# resolver/resolver_ans.py:45-46 at bc8a0746f2
def soa(qname: dns.name.Name | str) -> dns.rrset.RRset:
    return rrset(qname, dns.rdatatype.SOA, ". . 0 0 0 0 0")

# chain/ans4/ans.py:106-109 at bc8a0746f2
    @classmethod
    def rrsig(
        cls, owner: dns.name.Name, rrtype: dns.rdatatype.RdataType
    ) -> dns.rrset.RRset:
```

### Read the matcher back instead of repeating its constant

A handler whose answer carries the name or the type it matches takes
it from its matcher instead of spelling it a second time, so that the
two cannot drift apart.  A single-value matcher gives it back as
`qname`, `qtype` or `domain` for the class body; what a query matched
is `matched_domain` and `matched_label`, for `get_responses()`.  A
name derived from the matched one, the name server under it or the
zone above it, is derived from it too, with an f-string or
`parent()`.  The root is spelled `"."`: the literal is the clearer of
the two.

#### Examples

Single-response handlers that spelled the name they match again in
the record, d524d6b475.  Before:

```python
# resend_loop/ans3/ans.py:51-54 before d524d6b475
class ExampleNsHandler(SingleResponseHandler):
    matcher = Qname("example.") & Qtype(dns.rdatatype.NS)
    answer = [ns("example.", "ns.example.")]
    additional = [a("ns.example.", ANS3.ip)]

# serve_stale/ans2/ans.py:54-56 before d524d6b475
class OthertypeExampleCaaHandler(SingleResponseHandler):
    matcher = Qname("othertype.example.") & Qtype(dns.rdatatype.CAA)
    answer = [caa("othertype.example.", '0 issue "ca1.example.net"', ttl=2)]
```

After, the owner is the matcher's name, and the name server's name is
derived from it:

```python
# resend_loop/ans3/ans.py:51-54 at d524d6b475
class ExampleNsHandler(SingleResponseHandler):
    matcher = Qname("example.") & Qtype(dns.rdatatype.NS)
    answer = [ns(matcher.of(Qname).qname, f"ns.{matcher.of(Qname).qname}")]
    additional = [a(f"ns.{matcher.of(Qname).qname}", ANS3.ip)]

# serve_stale/ans2/ans.py:54-56 at d524d6b475
class OthertypeExampleCaaHandler(SingleResponseHandler):
    matcher = Qname("othertype.example.") & Qtype(dns.rdatatype.CAA)
    answer = [caa(matcher.of(Qname).qname, '0 issue "ca1.example.net"', ttl=2)]
```

The zone above the matched name, same commit.  Before:

```python
# fwdfirst/ans2/ans.py:22-25 before d524d6b475
class PoisonReferralForwarder(SingleResponseHandler):
    matcher = Domain("fwd.hack.")
    authority = [ns("hack.", "ns.fwd.hack.")]
    additional = [a("ns.fwd.hack.", ANS3.ip)]

# serve_stale/ans2/ans.py:34-37 before d524d6b475
class NxdomainExampleHandler(SingleResponseHandler):
    matcher = Qname("nxdomain.example.")
    rcode = dns.rcode.NXDOMAIN
    authority = [soa("example.", ttl=2)]
```

After:

```python
# fwdfirst/ans2/ans.py:22-25 at d524d6b475
class PoisonReferralForwarder(SingleResponseHandler):
    matcher = Domain("fwd.hack.")
    authority = [ns(matcher.domain.parent(), f"ns.{matcher.domain}")]
    additional = [a(f"ns.{matcher.domain}", ANS3.ip)]

# serve_stale/ans2/ans.py:34-37 at d524d6b475
class NxdomainExampleHandler(SingleResponseHandler):
    matcher = Qname("nxdomain.example.")
    rcode = dns.rcode.NXDOMAIN
    authority = [soa(matcher.qname.parent(), ttl=2)]
```

The same in `get_responses()`, same commit.  Before:

```python
# reclimit/reclimit_ans.py:88-94 before d524d6b475
class CountHandler(ReclimitHandler):
    matcher = Qname("count.")

    async def _get_counted_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        count_rrset = rrset("count.", dns.rdatatype.TXT, f"{self._state.count}", ttl=0)
```

After:

```python
# reclimit/reclimit_ans.py:88-99 at d524d6b475
class CountHandler(ReclimitHandler):
    matcher = Qname("count.")

    async def _get_counted_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        count_rrset = rrset(
            self.matcher.of(Qname).qname,
            dns.rdatatype.TXT,
            f"{self._state.count}",
            ttl=0,
        )
```

A value the matcher already checked, parsed from the name a second
time, 4dc458ee47.  Before:

```python
# statschannel/ans5/ans.py:75-79 before 4dc458ee47
class DelayedAHandler(AHandler):
    matcher = Domain("latency.example2.") & DelayLabel() & Qtype(dns.rdatatype.A)

    def delay(self, qctx: QueryContext) -> float:
        return int(qctx.qname.labels[0]) / 1000
```

After, the predicate keeps the label it matched, and the handler reads
it back:

```python
# statschannel/ans5/ans.py:77-82 at 4dc458ee47
class DelayedAHandler(AHandler):
    matcher = Domain("latency.example2.") & DelayLabel() & Qtype(dns.rdatatype.A)

    @property
    def delay(self) -> float:
        return int(self.matcher.of(DelayLabel).matched_label) / 1000
```

#### Negative examples

The root spelled as the literal it is:

```python
# resend_loop/ans3/ans.py:45-48 at d524d6b475
class RootNsHandler(SingleResponseHandler):
    matcher = Qname(".") & Qtype(dns.rdatatype.NS)
    answer = [ns(".", "a.root-servers.nil.")]
    additional = [a("a.root-servers.nil.", ANS3.ip)]
```

### A handler declares only what its base class reads

A handler's class body reads as a declaration of what it sends, so an
attribute in it that nothing reads misleads: it looks like a part the
framework sends, or a setting some code consults, and it is neither.
The class body therefore holds only the attributes its base class reads:
`matcher`, and for a `SingleResponseHandler` the parts of the response,
`answer`, `authority`, `additional`, `rcode`, `authoritative`, `delay`
and `edns`.  A base class of the server's own may read more, as a delay
or a limit its subclasses set.  A value a part is built from is not an
attribute of its own: it is spelled inline, as an f-string when it is
derived from another, or it is a module constant or a builder's default
when several handlers share it.

#### Examples

A handler keeping the name server's name it derives from its matcher
in an attribute of its own, `ns_name` (synthetic).  Before:

```python
# ans2/ans.py, before (synthetic)
class ReferralHandler(SingleResponseHandler):
    matcher = Domain("sub.example.")
    ns_name = prepend_label("ns", matcher.domain)
    authority = [ns(matcher.domain, ns_name.to_text())]
    additional = [a(ns_name, ANS3.ip)]
```

After, the derived name is spelled where it is used:

```python
# ans2/ans.py, after (synthetic)
class ReferralHandler(SingleResponseHandler):
    matcher = Domain("sub.example.")
    authority = [ns(matcher.domain, f"ns.{matcher.domain}")]
    additional = [a(f"ns.{matcher.domain}", ANS3.ip)]
```

### No wall of constants

A value used once lives at its use site; a value that is an input of a
helper is its default argument; a parameter read by one class is a class
constant on that class; what the zone already says is read from the
zone; what the framework already names is imported from it.  A module
constant is for what several places in the module share, or for a value
whose name says what the literal cannot, as `KEY_WITH_BAD_DATA` does.

#### Examples

A proxy that opened with a block of module constants, 0bd39806aa.  Before:
the listening address the framework provides, a zone file path, and
the NSEC3 parameters copied by hand from the signed zone:

```python
# nsec3/ans7/ans.py:56-73 before 0bd39806aa
IP = sys.argv[1]
PORT = int(sys.argv[2])
TARGET_NEXT_LENGTH = 200
ZONE_FILE = "../ns6/evil.test.db.signed"

# NSEC3 params: alg=1(SHA1), flags=1(opt-out), iterations=10, salt=DEADBEEF
NSEC3_ALG = 1
NSEC3_FLAGS = 1
NSEC3_ITERATIONS = 10
NSEC3_SALT = bytes.fromhex("DEADBEEF")
NSEC3_TTL = 86400

# RRSIG timing: computed dynamically for portability
NOW = int(time.time())
RRSIG_LABELS = 3
RRSIG_ORIG_TTL = 86400
RRSIG_INCEPTION = NOW - 3600  # 1 hour ago
RRSIG_EXPIRATION = NOW + 30 * 86400  # 30 days from now
```

After, the values the attack needs are constants of the class that
performs it, and the NSEC3 parameters come from the record being
tampered with:

```python
# nsec3/ans7/ans.py:67-78 at 0bd39806aa
    ZONE = "evil.test."
    NSEC3_TTL = 86400

    # Crafted NSEC3 next-hash length; exceeds the validator's 155-byte buffer.
    CRAFTED_NEXT_LENGTH = 200
    # Crafted NSEC3 type bitmap.
    CRAFTED_WINDOWS = Bitmap.from_text(dns.tokenizer.Tokenizer("A RRSIG")).windows

    # RRSIG validity window, computed at startup for portability.
    _NOW = int(time.time())
    RRSIG_INCEPTION = _NOW - 3600
    RRSIG_EXPIRATION = _NOW + 30 * 86400

# nsec3/ans7/ans.py:141-150 at 0bd39806aa
        return NSEC3(
            nsec3.rdclass,
            nsec3.rdtype,
            nsec3.algorithm,
            nsec3.flags,
            nsec3.iterations,
            nsec3.salt,
            padded_next,
            tuple(nsec3.windows if windows is None else windows),
        )
```

Names spelled next to the zone they belong to, d1b8282fdf.  Before:

```python
# nsupdate/ans11/ans.py:22-24 before d1b8282fdf
ZONE = "sigaxfr.nil."
NS_NAME = "ns.sigaxfr.nil."
HOST = "host.sigaxfr.nil."

# nsupdate/ans11/ans.py:51-57 before d1b8282fdf
def sig() -> dns.rrset.RRset:
    return dns.rrset.from_rdata(
        HOST,
        600,
        sig_rdata(dns.rdatatype.A),
        sig_rdata(dns.rdatatype.MX),
    )
```

After, the name server's name is derived from the zone instead of
spelled a second time, and the SIG(0) owner is the default argument
of its builder:

```python
# nsupdate/ans11/ans.py:22-23 at d1b8282fdf
ZONE = "sigaxfr.nil."
NS_NAME = f"ns.{ZONE}"

# nsupdate/ans11/ans.py:50-56 at d1b8282fdf
def sig(owner: str = f"host.{ZONE}") -> dns.rrset.RRset:
    return dns.rrset.from_rdata(
        owner,
        600,
        sig_rdata(dns.rdatatype.A),
        sig_rdata(dns.rdatatype.MX),
    )
```

Values read by one class each, a8b8712ff3.  Before, three zone names
and two DNSKEY blobs at module level:

```python
# xfer/ans9/ans.py:34-43 before a8b8712ff3
RECONFIG_ZONE = "xfr-and-reconfig."
RETRY_ZONE = "retry-too-big."
OVERRUN_ZONE = "private-dns-overrun."

# The malformed DNSKEY's algorithm identifier finishes on a 00 byte in the
# record that follows it in the same message.  That following record, the
# well-formed DNSKEY, starts with a compression pointer followed by the type,
# which starts with 00.
OVERRUN_DNSKEY = "\\# 12 00 00 00 fd 09 00 00 00 00 00 00 00"
WELL_FORMED_DNSKEY = "\\# 12 00 00 00 fd 06 00 00 00 00 00 00 00"

# xfer/ans9/ans.py:145-150 before a8b8712ff3
class OverrunAxfrHandler(ZoneAxfrHandler):
    """
    Serve the malformed PRIVATEDNS DNSKEY overrun; see OVERRUN_DNSKEY.
    """

    zone = OVERRUN_ZONE
```

After, each handler carries its own, and the comment sits with the
values it explains:

```python
# xfer/ans9/ans.py:134-146 at a8b8712ff3
class OverrunAxfrHandler(ZoneAxfrHandler):
    """
    Serve the malformed PRIVATEDNS DNSKEY overrun; see OVERRUN_DNSKEY.
    """

    zone = "private-dns-overrun."

    # The malformed DNSKEY's algorithm identifier finishes on a 00 byte in the
    # record that follows it in the same message.  That following record, the
    # well-formed DNSKEY, starts with a compression pointer followed by the
    # type, which starts with 00.
    OVERRUN_DNSKEY = "\\# 12 00 00 00 fd 09 00 00 00 00 00 00 00"
    WELL_FORMED_DNSKEY = "\\# 12 00 00 00 fd 06 00 00 00 00 00 00 00"
```

Addresses spelled by number, de201c80d8; `NS3.ip` and `ANS11.ip` are
`isctest.template`'s, and the address that is nobody's stays a
literal.  Before:

```python
# cyclic_glue/ans5/ans.py:47-55 before de201c80d8
    additional = [
        a("ns.foo.test.", "10.53.0.3"),
        # These glues don't belong, as they're outside the
        # delegated domain. However, only the latest will be
        # ignored by the resolver (the former, being a sibling
        # glue, is still used.)
        a("ns.bar.test.", "10.53.0.3"),
        a("ns.test2.", "10.10.10.10"),
    ]
```

After:

```python
# cyclic_glue/ans5/ans.py:48-56 at de201c80d8
    additional = [
        a("ns.foo.test.", NS3.ip),
        # These glues don't belong, as they're outside the
        # delegated domain. However, only the latest will be
        # ignored by the resolver (the former, being a sibling
        # glue, is still used.)
        a("ns.bar.test.", NS3.ip),
        a("ns.test2.", "10.10.10.10"),
    ]

# nsupdate/ans11/ans.py:75-79 at de201c80d8
    zone_contents = [
        rrset(ZONE, dns.rdatatype.NS, NS_NAME),
        rrset(NS_NAME, dns.rdatatype.A, ANS11.ip),
        sig(),
    ]
```
