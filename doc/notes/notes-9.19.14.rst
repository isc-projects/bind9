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

Notes for BIND 9.19.14
----------------------

Security Fixes
~~~~~~~~~~~~~~

- The overmem cleaning process has been improved, to prevent the cache from
  significantly exceeding the configured :any:`max-cache-size` limit.
  :cve:`2023-2828`

  ISC would like to thank Shoham Danino from Reichman University, Anat
  Bremler-Barr from Tel-Aviv University, Yehuda Afek from Tel-Aviv University,
  and Yuval Shavitt from Tel-Aviv University for bringing this vulnerability to
  our attention.  :gl:`#4055`

New Features
~~~~~~~~~~~~

- The read timeout in :iscman:`rndc` can now be specified on the command
  line using the :option:`-t <rndc -t>` option, allowing commands that
  take a long time to complete sufficient time to do so. :gl:`#4046`

- Support for multi-signer model 2 (:rfc:`8901`) when using
  :any:`inline-signing` was added. :gl:`#2710`

- A new option to :any:`dnssec-policy` has been added, :any:`cdnskey`,
  that allows users to enable or disable the publication of CDNSKEY
  records. :gl:`#4050`

- The system test suite can now be executed with pytest (along with
  pytest-xdist for parallel execution). :gl:`#3978`

Removed Features
~~~~~~~~~~~~~~~~

- Special-case code that was originally added to allow GSS-TSIG to work
  around bugs in the Windows 2000 version of Active Directory has now
  been removed, since Windows 2000 is long past end-of-life. The
  :option:`-o <nsupdate -o>` option and the ``oldgsstsig`` command to
  :iscman:`nsupdate` have been deprecated, and are now treated as
  synonyms for :option:`-g <nsupdate -g>` and ``gsstsig`` respectively.
  :gl:`#4012`

Feature Changes
~~~~~~~~~~~~~~~

- If a response from an authoritative server has its RCODE set to
  FORMERR and contains an echoed EDNS COOKIE option that was present in
  the query, :iscman:`named` now retries sending the query to the
  same server without an EDNS COOKIE option. :gl:`#4049`

- The responsiveness of :iscman:`named` was improved, when serving as an
  authoritative DNS server for a delegation-heavy zone(s) shortly after
  loading such zone(s). :gl:`#4045`

Bug Fixes
~~~~~~~~~

- When the :any:`stale-answer-enable` option was enabled and the
  :any:`stale-answer-client-timeout` option was enabled and larger than
  0, :iscman:`named` previously allocated two slots from the
  :any:`clients-per-query` limit for each client and failed to gradually
  auto-tune its value, as configured. This has been fixed. :gl:`#4074`

- Previously, it was possible for a delegation from cache to be returned
  to the client after the :any:`stale-answer-client-timeout` duration.
  This has been fixed. :gl:`#3950`

- BIND could allocate too big buffers when sending data via
  stream-based DNS transports, leading to increased memory usage.
  This has been fixed. :gl:`#4038`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
