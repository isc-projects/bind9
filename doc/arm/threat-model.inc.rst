.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

.. _threat_model:

Threat Model
------------
This section explains how to deploy BIND safely and evaluate potential
vulnerabilities. It evolves with the attack landscape and our understanding.

Security Boundary
~~~~~~~~~~~~~~~~~
Unless stated otherwise below, network data is untrusted and subject to safety
and correctness checks. No input, even malformed, should crash the server or
significantly affect other conforming traffic.

BIND 9 assumes only administrators can access:

- All files: zone, configuration, key, temporary, etc.
- Command-line arguments, environment, and standard input of BIND programs
- Authenticated :any:`controls` connections
- :any:`statistics-channels`
- Sockets used for :any:`update-policy` type ``external``
- Write access to :ref:`response policy <rpz>` and :ref:`catalog <catz-info>`
  zone content

Unauthorized access or misuse can cause arbitrary misbehavior and is not a
basis for CVE assignment or security-sensitive handling.

Client tools (:iscman:`dig`, :iscman:`delv`, :iscman:`nsupdate`, ...) are
run by a user against servers of the user's choosing. Crashes (including
assertion failures), hangs, and wrong output caused by malicious
responses are ordinary bugs.

Non-Standard Behavior
~~~~~~~~~~~~~~~~~~~~~
The DNS protocol does not define some behavior, such as handling responses
from non-conforming servers. BIND fills these gaps with its own safety checks
and limits, subject to change as the protocol and deployments evolve.

Unexpected behavior limited to zones on non-conforming servers, not affecting
traffic to conforming servers and zones, is not a security issue *in BIND*.

Unsupported Features
~~~~~~~~~~~~~~~~~~~~
Not a basis for CVE assignment or security-sensitive handling:

- Problems triggered only by resources (views, zones, ...) with classes other
  than Internet (IN), such as CHAOS (CH) or HESIOD (HS)
- Misbehavior of incorrectly implemented custom :any:`dlz`, :any:`dyndb`, or
  :any:`plugin` modules
- Problems reproducible only in non-standard builds (sanitizers, developer
  mode) with no corresponding effect in a release build, e.g., a benign data
  race reported by TSAN
- Test code, sample and contrib modules
- Compile-time options not exposed by the build system
- Library code reachable only through calls BIND programs do not make

Authoritative Servers
~~~~~~~~~~~~~~~~~~~~~
:any:`primaries` and :ref:`UPDATE <dynamic_update>` clients (within their
:any:`authorization <update-policy>`) are partially trusted: they may break
data they control and consume resources up to configured limits, but should
not otherwise affect other conforming zones or crash the server. By protocol
design, content of :ref:`catalog zones <catz-info>` affects the set of served
zones, so their primaries and :ref:`UPDATE <dynamic_update>` clients are
administrators (see `Security Boundary`_).

Authoritative zone limits are intentionally lenient by default (unlimited size,
long transfer timeouts, etc.). Resource exhaustion within configured limits is
not a security issue. Set options in :ref:`server_resource_limits` and
:ref:`zone_transfers` to fit the deployment, including zones where malicious
clients may be authorized for :ref:`dynamic_update`.

Depending on configuration, :ref:`NOTIFY <notify>` and DS checks
(:any:`checkds`, :any:`parental-agents`) can trigger outgoing queries, making
the authoritative server act as a resolver. Resolver assumptions then apply.

Recursive Resolvers
~~~~~~~~~~~~~~~~~~~
Resolvers are inherently amplifiers: they legitimately send more traffic and do
more work than the triggering client traffic. DNS specifications set no
amplification limits, so BIND sets its own. Staying within
:any:`max-query-count` outgoing queries per client query is not a security
issue. Other amplification is evaluated against `Performance Impact`_
baselines.

:ref:`server_resource_limits` limit damage from misbehaving authoritative
servers. All these limits balance interoperability and attack protection, are
subject to change as deployments evolve, and can temporarily break resolution
of zones with excessively complex configurations or resolution paths.

By protocol design, content of :ref:`response policy <rpz>` zones can
rewrite the answer to any query, so their primaries and UPDATE clients are
administrators (see `Security Boundary`_).

Forwarding Resolvers
~~~~~~~~~~~~~~~~~~~~
:any:`forwarders` are trusted for their name subtree: they can make its names
unresolvable, provide fake data, and see forwarded queries.

Data Integrity and Confidentiality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Zones not DNSSEC-secure (:rfc:`4033`) are spoofable, trivially by on-path
attackers. Against off-path attackers, BIND applies only :rfc:`5452` measures,
such as port and message ID randomization, and DNS COOKIES (:rfc:`7873`,
:any:`send-cookie`) if both sides support them. Detecting traffic manipulation
and data coherency issues is out of scope.

Source port randomization relies on the operating system, whose weaknesses
(e.g., side channels revealing ephemeral ports) are out of scope.

DNSSEC provides data origin authentication and integrity, not confidentiality
or availability against packet-manipulating attackers.

By DNS protocol definition, ancestors of the attacked zone are implicitly
trusted. Misbehaving ones can always break resolution or sign fake data if
DNSSEC is in use. BIND does not detect or defend against this.

:ref:`tsig` and authenticated :any:`tls` provide integrity in transit. TLS also
provides confidentiality. Without either, attackers can impersonate configured
servers.

Performance Impact
~~~~~~~~~~~~~~~~~~
Attackers can send BIND large or very expensive-to-process data. As researcher
Felix Linker put it, "A DNS resolver is essentially an interpreter executing a
program provided by an attacker over the network." Resource usage within
configured limits is not a security issue.

Availability and performance impact are measured against three baselines:

- resolver cache hit / authoritative response
- pseudo-random subdomain attack (PRSD, i.e., 100% negative responses)
- large positive response (with or without wildcard)

Any attacker can trivially execute these, so scenarios not significantly
worse than the worst of the three gain attackers nothing and are not a basis
for CVE assignment. Report them anyway if otherwise interesting, e.g.,
as optimization opportunities.

Resource-limit bug severity is evaluated against the same baselines. Attacks
are compared with baselines over the same transport.

CVSS Scoring Guidelines
~~~~~~~~~~~~~~~~~~~~~~~
See https://kb.isc.org/docs/isc-cvss-scoring-guidelines
