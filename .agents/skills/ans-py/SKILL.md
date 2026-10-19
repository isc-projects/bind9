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
