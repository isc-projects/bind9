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

Notes for BIND 9.21.3
---------------------

New Features
~~~~~~~~~~~~

- Add separate query counters for new protocols.

  Add query counters for DoT, DoH, unencrypted DoH and their proxied
  counterparts. The new protocols do not update their respective TCP/UDP
  transport counter. The previously existing counters are now dedicated
  for TCP/UDP over plain port 53 only. :gl:`#598`

- Implement :rfc:`9567`: EDNS Report-Channel option.

  Add new :namedconf:ref:`send-report-channel` and :namedconf:ref:`log-report-channel` options.

  :namedconf:ref:`send-report-channel` specifies an *agent domain*, to which error
  reports can be sent by querying a specially constructed name within
  the agent domain. The EDNS Report-Channel option has been added to
  outgoing authoritative responses, to inform clients where to send such
  error reports in the event of a problem.

  If a :namedconf:ref:`zone` is configured which matches the *agent domain* and has
  :namedconf:ref:`log-report-channel` set to `yes`, error-reporting queries will be
  logged at level `info` to the `dns-reporting-agent` logging :namedconf:ref:`channel`.
  :gl:`#3659`

- Add detailed debugging of :namedconf:ref:`update-policy` rule matching.

  This logs how :iscman:`named` determines whether an update request is granted or
  denied when using update-policy. :gl:`#4751`

- Update built-in :file:`bind.keys` file with the new 2025 `IANA root key
  <https://www.iana.org/dnssec/files>`_.

  Add an `initial-ds` entry to :file:`bind.keys` for the new root key, ID
  38696, which is scheduled for publication in January 2025. :gl:`#4896`

- Enable runtime selection of FIPS mode in :iscman:`dig` and delv.

  :option:`dig -F` and :option:`delv -F` can now be used to select FIPS mode at
  runtime. :gl:`#5046`

Removed Features
~~~~~~~~~~~~~~~~

- Move contributed DLZ modules into a separate repository. DLZ modules should
  not be used except in testing.

  The DLZ modules were not maintained, the DLZ interface itself is going to be
  scheduled for removal, and the DLZ interface is blocking. Any module that
  blocks the query to the :namedconf:ref:`database` blocks the whole server.

  The DLZ modules now live in
  https://gitlab.isc.org/isc-projects/dlz-modules repository.
  :gl:`#4865`

- Remove RBTDB implementation.

  Remove the RBTDB :namedconf:ref:`database` implementation, and only leave the
  QPDB-based implementations of :namedconf:ref:`zone` and cache databases. This means it is no
  longer possible to choose RBTDB as the default database at compilation
  time, nor to configure RBTDB as the :namedconf:ref:`database` backend
  in the configuration file. :gl:`#5027`

Feature Changes
~~~~~~~~~~~~~~~

- :iscman:`dnssec-ksr` now supports KSK rollovers.

  The tool now allows for KSK generation, as well as planned KSK rollovers.
  When signing a bundle from a Key Signing Request (KSR), only the
  key that is active in that time frame is
  used for signing. Also, the CDS and CDNSKEY records are now added and
  removed at the correct time. :gl:`#4697`  :gl:`#4705`

- Add `none` parameter to :namedconf:ref:`query-source` and
  :namedconf:ref:`query-source-v6` to disable IPv4 or IPv6 upstream queries but
  allow listening to queries from clients on IPv4 or IPv6.

- Print :rfc:`7314`: EXPIRE option in transfer summary. :gl:`#5013`

- Add missing EDNS option mnemonics to :iscman:`dig`.

  The `Report-Channel` and `ZONEVERSION` options can now be sent
  using `dig +ednsopt=report-channel` (or `dig +ednsopt=rc` for short),
  and `dig +ednsopt=zoneversion`.

  Several other EDNS option names, including `DAU`, `DHU`, `N3U`, and
  `CHAIN`, are now displayed correctly in text and YAML formats.

  Also, an inconsistency has been corrected: the `TCP-KEEPALIVE` option is now
  spelled with a hyphen in both text and YAML formats; previously, text
  format used a space.

- Add new :namedconf:ref:`logging` module for crypto errors in libisc.

  Add a new `crypto` log module to be used for low-level
  cryptographic operations. The DNS-related cryptography logs are still
  logged in the 'dns/crypto' module.

- Emit more helpful log messages for exceeding :namedconf:ref:`max-records-per-type`.

  The new log message is emitted when adding or updating an RRset fails
  due to exceeding the :namedconf:ref:`max-records-per-type` limit. The log includes the
  owner name and type, corresponding zone name, and the limit value. It
  will be emitted on loading a zone file, inbound zone transfer (both
  AXFR and IXFR), handling a DDNS update, or updating a cache DB. It's
  especially helpful in the case of zone transfer, since the secondary
  side doesn't have direct access to the offending zone data.

  It could also be used for :namedconf:ref:`max-types-per-name`, but this change doesn't
  implement it yet as it's much less likely to happen in practice.

- Harden key management when key files have become unavailable.

  Prior to doing key management, BIND 9 will check if the key files on
  disk match the expected keys. If key files for previously observed
  keys have become unavailable, this will prevent the internal key
  manager from running.

- Reduce memory footprint by optimizing commonly-used data structures.
  :gl:`#5022`

Bug Fixes
~~~~~~~~~

- Use TLS for notifies if configured to do so.

  Notifies configured to use TLS will now be sent over TLS, instead of
  plain text UDP or TCP. Also, failing to load the TLS configuration for
  :namedconf:ref:`notify` now results in an error. :gl:`#4821`

- `{&dns}` is as valid as `{?dns}` in a SVCB's dohpath.

  :iscman:`dig` failed to parse a valid `SVCB` record with a `dohpath` URI
  template containing a `{&dns}`, like `dohpath=/some/path?key=value{&dns}"`.
  :gl:`#4922`

- Fix NSEC3 closest encloser lookup for names with empty non-terminals.

  A previous performance optimization for finding the NSEC3 closest encloser
  when generating authoritative responses could cause servers to return
  incorrect NSEC3 records in some cases. This has been fixed.
  :gl:`#4950`

- Report client transport in :option:`rndc recursing` output

  When :option:`rndc recursing` is used to dump the list of recursing
  clients, it now indicates whether a query was sent via UDP, TCP,
  TLS, or HTTP.
  :gl:`#4971`

- :namedconf:ref:`recursive-clients` statement with value 0 triggered an assertion failure.

  BIND 9.20.0 broke `recursive-clients 0;`.  This has now been fixed.
  :gl:`#4987`

- Parsing of hostnames in :iscman:`rndc.conf` was broken.

  When DSCP support was removed, parsing of hostnames in :iscman:`rndc.conf` was
  accidentally broken, resulting in an assertion failure.  This has been
  fixed. :gl:`#4991`

- :iscman:`dig` options of the form `[+-]option=<value>` failed to display the
  value on the printed command line. This has been fixed. :gl:`#4993`

- Provide more visibility into TLS configuration errors by logging
  `SSL_CTX_use_certificate_chain_file()` and `SSL_CTX_use_PrivateKey_file()`
  errors individually. :gl:`#5008`

- Fix a race condition when canceling ADB find which could cause an assertion
  failure. :gl:`#5024`

- Fix doubled memory usage during incoming zone transfer. :gl:`#4986`

- SERVFAIL cache memory cleaning is now more aggressive; it no longer consumes a
  lot of memory if the server encounters many SERVFAILs at once.
  :gl:`#5025`

- Fix trying the next primary XoT server when the previous one was marked as
  unreachable.

  In some cases :iscman:`named` failed to try the next primary
  server in the :namedconf:ref:`primaries` list when the previous one was marked as
  unreachable. This has been fixed. :gl:`#5038`
