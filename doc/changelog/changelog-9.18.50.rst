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

BIND 9.18.50
------------

Security Fixes
~~~~~~~~~~~~~~

- Fix DNS64 owner case after DNAME restart. ``74c46fd139``

  When BIND 9 is configured to use DNS64 and encounters a DNAME
  redirect, it could end up using freed memory for the DNS response
  owner name. This caused the response to contain corrupted data. This
  fix ensures the correct owner name is used when constructing the
  synthesized response after a DNAME redirect.

  ISC thanks Qifan Zhang of Palo Alto Networks for reporting the issue.
  :gl:`#5934`

New Features
~~~~~~~~~~~~

- Enable PR-Agent reviews on merge requests. ``d850afcbf4``

  Adds a CI job that runs PR-Agent against each merge request opened
  from the canonical repository, posting an automated review and
  code-improvement suggestions as MR comments. The job is gated to
  same-project source branches so the OpenAI key and personal access
  token are not exposed to fork pipelines. :gl:`!12036`

Removed Features
~~~~~~~~~~~~~~~~

- Remove ineffective TCP fallback after repeated UDP timeouts.
  ``9b53e4be29``

  When an authoritative server failed to respond to two consecutive UDP
  queries, named marked the next retry as TCP but still sent it over
  UDP, producing misleading dnstap records. The ineffective retry path
  has been removed; a corrected TCP fallback will be restored in future
  BIND 9 versions. :gl:`#5529` :gl:`!12050`

- Remove useless PR-Agent jobs. ``d329d25548``

  The experiment was a failure, the PR-Agent doesn't send a full context
  to the AI Agents and the results are abysmal because of that.
  :gl:`!12121`

Feature Changes
~~~~~~~~~~~~~~~

- Fall back to TCP on a UDP response with a mismatched query id.
  ``f175d8c63b``

  BIND used to wait silently for the correct DNS message id on a UDP
  fetch even after receiving a response from the expected server with
  the wrong id, leaving room for off-path spoofing attempts to keep
  guessing within that window.  The resolver now retries the fetch over
  TCP on the first such response, and a new MismatchTCP statistics
  counter tracks how often the fallback fires. :gl:`#5449` :gl:`!12026`

Bug Fixes
~~~~~~~~~

- Clear REDIRECT flag when it isn't needed. ``11b47f9b7e``

  When `nxdomain-redirect` is in use, and a recursive query is used to
  get the redirected answer, a flag is set to distinguish it from a
  normal recursive response. Previously, that flag was left set
  afterward, which could trigger an assertion if a normal recursive
  query was sent later on behalf of the same client: for example,
  because the `filter-aaaa` plugin was in use.  This has been fixed.
  :gl:`#5936` :gl:`!12077`

- Validate nsec3hash arguments instead of relying on atoi()
  ``73bf578b01``

  The nsec3hash tool parsed its algorithm, flags, and iterations
  arguments with atoi(), then range-checked the result. For values that
  overflow int during digit-by-digit accumulation, atoi() is undefined;
  in practice on musl libc the modular wrap leaves n == 0, which
  silently passes the "iterations > 0xffffU" check. On Alpine Linux this
  made nsec3hash succeed with iterations treated as 0 for inputs like
  4294967296 (2^32).

  The latent bug only surfaced when the recent image rebuild pulled in
  Hypothesis 6.152.9 (2026-05-19), which unified the distribution used
  for bounded and unbounded integers() strategies. The new smoother
  distribution explores the 2^32 boundary on unbounded ranges like
  integers(min_value=65536); earlier versions did not reach there, so
  test_nsec3hash_too_many_iterations only started failing on Alpine
  after the image refresh.

  Replace the three atoi() calls with isc_parse_uint8 /
  isc_parse_uint16, which uniformly reject overflow, trailing garbage,
  leading sign, and non-numeric input across libc implementations. As a
  side effect, error messages now include the offending argument and a
  specific reason ("out of range" vs "not a valid number").

  Assisted-by: Claude:claude-opus-4-7 :gl:`#6013` :gl:`!12075`


