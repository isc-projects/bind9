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

BIND 9.21.3
-----------

New Features
~~~~~~~~~~~~

- Add separate query counters for new protocols. ``419aa3264e``

  Add query counters for DoT, DoH, unencrypted DoH and their proxied
  counterparts. The new protocols do not update their respective TCP/UDP
  transport counter and is now for TCP/UDP over plain 53 only.
  :gl:`#598` :gl:`!9585`

- Implement RFC 9567: EDNS Report-Channel option. ``e1588022c1``

  Add new `send-report-channel` and `log-report-channel` options.
  `send-report-channel` specifies an agent domain, to which error
  reports can be sent by querying a specially constructed name within
  the agent domain. EDNS Report-Channel options will be added to
  outgoing authoritative responses, to inform clients where to send such
  queries in the event of a problem.

  If a zone is configured which matches the agent domain and has
  `log-report-channel` set to `yes`, error-reporting queries will be
  logged at level `info` to the `dns-reporting-agent` logging channel.
  :gl:`#3659` :gl:`!7036`

- Add detailed debugging of update-policy rule matching. ``80f611afe6``

  This logs how named determines if an update request is granted or
  denied when using update-policy. :gl:`#4751` :gl:`!9074`

- Update bind.keys with the new 2025 IANA root key. ``63ee8979a7``

  Add an 'initial-ds' entry to bind.keys for the new root key, ID 38696,
  which is scheduled for publication in January 2025. :gl:`#4896`
  :gl:`!9422`

- Support jinja2 templates in pytest runner. ``04bdaf6efb``

  Configuration files in system tests which require some variables (e.g.
  port numbers) filled in during test setup, can now use jinja2
  templates when `jinja2` python package is available.

  Any `*.j2` file found within the system test directory will be
  automatically rendered with the environment variables into a file
  without the `.j2` extension by the pytest runner. E.g.
  `ns1/named.conf.j2` will become `ns1/named.conf` during test setup. To
  avoid automatic rendering, use `.j2.manual` extension and render the
  files manually at test time.

  New `templates` pytest fixture has been added. Its `render()` function
  can be used to render a template with custom test variables. This can
  be useful to fill in different config options during the test. With
  advanced jinja2 template syntax, it can also be used to include/omit
  entire sections of the config file rather than using `named1.conf.in`,
  `named2.conf.in` etc. :gl:`#4938` :gl:`!9587`

- Enable runtime selection of FIPS mode in dig and delv. ``2c1fb7e5eb``

  'dig -F' and 'delv -F' can now be used to select FIPS mode at runtime.
  :gl:`#5046` :gl:`!9754`

- Extended TCP accept() logging. ``cd312298ea``

  Add extra log messages about TCP connection management. :gl:`!9089`

Removed Features
~~~~~~~~~~~~~~~~

- Move contributed DLZ modules into a separate repository.
  ``0fa2807d2b``

  The DLZ modules are poorly maintained as we only ensure they can still
  be compiled, the DLZ interface is blocking, so anything that blocks
  the query to the database blocks the whole server and they should not
  be used except in testing.  The DLZ interface itself is going to be
  scheduled for removal.

  The DLZ modules now live in
  https://gitlab.isc.org/isc-projects/dlz-modules repository.
  :gl:`#4865` :gl:`!9349`

- Remove RBTDB implementation. ``a10d78db55``

  Remove the RBTDB database implementation, and only leave the QPDB
  based implementations of zone and cache databases.  This means it's no
  longer possible to choose the RBTDB to be default at the compilation
  time and it's not possible to configure RBTDB as the database backend
  in the configuration file. :gl:`#5027` :gl:`!9733`

- Remove namedconf port/tls deprecated check on `*-source[-v6]` options.
  ``29f1d4bb6f``

  The usage of port and tls arguments in `*-source` and `*-source-v6` named
  configuration options has been previously removed. Remove various
  configuration check deprecating usage of those arguments. :gl:`!9738`

- Remove unused <openssl/hmac.h> headers from OpenSSL shims.
  ``a1fed2d8e7``

  The <openssl/hmac.h> header was unused and including the header might
  cause build failure when OpenSSL doesn't have Engines support enabled.

  See https://fedoraproject.org/wiki/Changes/OpensslDeprecateEngine

  Removes unused hmac includes after Remove OpenSSL Engine support
  (commit ef7aba70) removed engine support. :gl:`!9228`

Feature Changes
~~~~~~~~~~~~~~~

- Use default listening rules from config.c string. ``f6148f66d4``

  Remove special code which creates default listeners, and use the
  normal named.conf configuration parser instead. This removes unneeded
  code and makes the built-in configuration text provide a true primary
  source of defaults. This change should be transparent to end-users and
  should not cause any visible change. :gl:`#1424` :gl:`!2663`

- Use lists of expected artifacts in system tests. ``32cc143da0``

  ``clean.sh`` scripts have been replaced by lists of expected artifacts
  for each system test module. The list is defined using the custom
  ``pytest.mark.extra_artifacts`` mark, which can use both filenames and
  globs. :gl:`#4261` :gl:`!9426`

- Dnssec-ksr now supports KSK rollovers. ``675a7f0166``

  The tool 'dnssec-ksr' now allows for KSK generation, as well as
  planned KSK rollovers. When signing a bundle from a Key Signing
  Request (KSR), only the key that is active in that time frame is being
  used for signing. Also, the CDS and CDNSKEY records are now added and
  removed at the correct time. :gl:`#4697`  :gl:`#4705` :gl:`!9452`

- Unify parsing of query-source and other X-source options.
  ``ff94eb9e31``

  The query-source option currently allows the address to be specified
  in two ways, either as every other X-source option, or as an "address"
  key-value pair. This merge request extends the `parse_sockaddrsub`
  config parsing function so that it can parse the query-source option.
  It also removes the separate config parsing function for
  `query-source`. :gl:`#4961` :gl:`!9551`

- Add none parameter to query-source and query-source-v6 to disable IPv4
  or IPv6 upstream queries. ``001272127f``

  Add a none parameter to named configuration option `query-source`
  (respectively `query-source-v6`) which forbid usage of IPv4
  (respectively IPv6) addresses when named is doing an upstream query.
  :gl:`#4981` Turning-off upstream IPv6 queries while still listening to
  downstream queries on IPv6. :gl:`!9727`

- Incrementally apply AXFR transfer. ``a3e03b52e2``

  Reintroduce logic to apply diffs when the number of pending tuples is
  above 128. The previous strategy of accumulating all the tuples and
  pushing them at the end leads to excessive memory consumption during
  transfer.

  This effectively reverts half of e3892805d6 :gl:`#4986` :gl:`!9740`

- Print expire option in transfer summary. ``d0900b7edf``

  The zone transfer summary will now print the expire option value in
  the zone transfer summary. :gl:`#5013` :gl:`!9694`

- Optimize memory layout of core structs. ``d94e88220c``

  Reduce memory footprint by: - Reordering struct fields to minimize
  padding. - Using exact-sized atomic types instead of
  `*_least`/`*_fast` variants - Downsizing integer fields where possible

  Affected structs: - dns_name_t - dns_slabheader_t  - dns_rdata_t -
  qpcnode_t - qpznode_t :gl:`#5022` :gl:`!9721`

- Add missing EDNS option mnemonics. ``887b04571b``

  The `Report-Channel` and `ZONEVERSION` EDNS options can now be sent
  using `dig +ednsopt=report-channel` (or `dig +ednsopt=rc` for short),
  and `dig +ednsopt=zoneversion`.

  Several other EDNS option names, including `DAU`, `DHU`, `N3U`, and
  `CHAIN`, are now displayed correctly in text and YAML formats. Also,
  an inconsistency has been corrected: the `TCP-KEEPALIVE` option is now
  spelled with a hyphen in both text and YAML formats; previously, text
  format used a space. :gl:`!9691`

- Add new logging module for logging crypto errors in libisc.
  ``cf930c23d0``

  Add a new 'crypto' log module that will be used for a low-level
  cryptographic operations.  The DNS related cryptography logs are still
  logged in the 'dns/crypto' module. :gl:`!9287`

- Add two new clang-format options that help with code formatting.
  ``94b65f5eb0``

  * Add new clang-format option to remove redundant semicolons
  * Add new clang-format option to remove redundant parentheses

  :gl:`!9749`

- Assume IPv6 is universally available (on the kernel level)
  ``b72a2300b9``

  Instead of various probing, just assume that IPv6 is universally
  available and cleanup the various checks and defines that we have
  accumulated over the years. :gl:`!9360`

- Emit more helpful log for exceeding max-records-per-type.
  ``b2ffa5845b``

  The new log message is emitted when adding or updating an RRset fails
  due to exceeding the max-records-per-type limit. The log includes the
  owner name and type, corresponding zone name, and the limit value. It
  will be emitted on loading a zone file, inbound zone transfer (both
  AXFR and IXFR), handling a DDNS update, or updating a cache DB. It's
  especially helpful in the case of zone transfer, since the secondary
  side doesn't have direct access to the offending zone data.

  It could also be used for max-types-per-name, but this change doesn't
  implement it yet as it's much less likely to happen in practice.
  :gl:`!9509`

- Enforce type checking for dns_dbversion_t. ``4b47c96a89``

  Originally, the dns_dbversion_t was typedef'ed to void type.  This
  allowed some flexibility, but using `(void *)` just removes any
  type-checking that C might have.  Instead of using:

  typedef void dns_dbversion_t;

  use a trick to define the type to non-existing structure:

  typedef struct dns_dbversion dns_dbversion_t;

  This allows the C compilers to employ the type-checking while the
  structure itself doesn't have to be ever defined because the actual
  'storage' is never accessed using dns_dbversion_t type. :gl:`!9724`

- Harden key management when key files have become unavailabe.
  ``7a416693bb``

  Prior to doing key management, BIND 9 will check if the key files on
  disk match the expected keys. If key files for previously observed
  keys have become unavailable, this will prevent the internal key
  manager from running. :gl:`!9337`

- Unify explicit fetching and libcrypto handling. ``94e5061151``

  Unify libcrypto initialization and explicit digest fetching in a
  single place.

  It will remove the remaining implicit fetching and deduplicate
  explicit fetching inside the codebase. Initialization has been moved
  in to ensure OpenSSL cleanup is done only after fetched contextes are
  destroyed. :gl:`!9288`

Bug Fixes
~~~~~~~~~

- Use TLS for notifies if configured to do so. ``4c882e4c0b``

  Notifies configured to use TLS will now be sent over TLS, instead of
  plaintext UDP or TCP. Also, failing to load the TLS configuration for
  notify now also results in an error. :gl:`#4821` :gl:`!9407`

- '{&dns}' is as valid as '{?dns}' in a SVCB's dohpath. ``8e0ec3fe0a``

  `dig` fails to parse a valid (as far as I can tell, and accepted by
  `kdig` and `Wireshark`) `SVCB` record with a `dohpath` URI template
  containing a `{&dns}`, like `dohpath=/some/path?key=value{&dns}"`. If
  the URI template contains a `{?dns}` instead `dig` is happy, but my
  understanding of rfc9461 and section 1.2. "Levels and Expression
  Types" of rfc6570 is that `{&dns}` is valid. See for example section
  1.2. "Levels and Expression Types" of rfc6570.

  Note that Peter van Dijk suggested that `{dns}` and
  `{dns,someothervar}` might be valid forms as well, so my patch might
  be too restrictive, although it's anyone's guess how DoH clients would
  handle complex templates. :gl:`#4922` :gl:`!9455`

- Make dns_validator_cancel() respect the data ownership. ``4c0e69ff01``

  There was a data race dns_validator_cancel() was called when the
  offloaded operations were in progress.  Make dns_validator_cancel()
  respect the data ownership and only set new .canceling variable when
  the offloaded operations are in progress.  The cancel operation would
  then finish when the offloaded work passes the ownership back to the
  respective thread. :gl:`#4926` :gl:`!9470`

- Fix NSEC3 closest encloser lookup for names with empty non-terminals.
  ``a33528fe99``

  The performance improvement for finding the NSEC3 closest encloser
  when generating authoritative responses could cause servers to return
  incorrect NSEC3 records in some cases. This has been fixed.
  :gl:`#4950` :gl:`!9610`

- Revert "Improve performance when looking for the closest encloser"
  ``3a321ec661``

  Revert "fix: chg: Improve performance when looking for the closest
  encloser when returning NSEC3 proofs"

  This reverts merge request !9436 :gl:`#4950` :gl:`!9611`

- Report client transport in 'rndc recursing' ``87ec2ce498``

  When `rndc recursing` is used to dump the list of recursing clients,
  it now indicates whether a query was sent via UDP, TCP, TLS, or HTTP.
  :gl:`#4971` :gl:`!9590`

- Fix a data race in dns_zone_getxfrintime() ``84eac93bfd``

  The dns_zone_getxfrintime() function fails to lock the zone before
  accessing its 'xfrintime' structure member, which can cause a data
  race between soa_query() and the statistics channel. Add the missing
  locking/unlocking pair, like it's done in numerous other similar
  functions. :gl:`#4976` :gl:`!9591`

- 'Recursive-clients 0;' triggers an assertion. ``d7fab54393``

  BIND 9.20.0 broke `recursive-clients 0;`.  This has now been fixed.
  :gl:`#4987` :gl:`!9621`

- Transport needs to be a selector when looking for an existing
  dispatch. ``a7df51b706``

  This allows for dispatch to use existing TCP/HTTPS/TLS etc. streams
  without accidentally using an unexpected transport. :gl:`#4989`
  :gl:`!9633`

- Parsing of hostnames in rndc.conf was broken. ``6ea2ac5f94``

  When DSCP support was removed, parsing of hostnames in rndc.conf was
  accidentally broken, resulting in an assertion failure.  This has been
  fixed. :gl:`#4991` :gl:`!9669`

- Restore values when dig prints command line. ``8467449407``

  Options of the form `[+-]option=<value>` failed to display the value
  on the printed command line. This has been fixed. :gl:`#4993`
  :gl:`!9653`

- Provide more visibility into configuration errors. ``54889fd2af``

  by logging SSL_CTX_use_certificate_chain_file and
  SSL_CTX_use_PrivateKey_file errors individually. :gl:`#5008`
  :gl:`!9683`

- Fix a data race between dns_zone_getxfr() and dns_xfrin_create()
  ``60ec9ef507``

  There is a data race between the statistics channel, which uses
  `dns_zone_getxfr()` to get a reference to `zone->xfr`, and the
  creation of `zone->xfr`, because the latter happens outside of a zone
  lock.

  Split the `dns_xfrin_create()` function into two parts to separate the
  zone transfer starting part from the zone transfer object creation
  part. This allows us to attach the new object to a local variable
  first, then attach it to `zone->xfr` under a lock, and only then start
  the transfer. :gl:`#5011` :gl:`!9716`

- Fix race condition when canceling ADB find. ``75f1587aed``

  When canceling the ADB find, the lock on the find gets released for a
  brief period of time to be locked again inside adbname lock.  During
  the brief period that the ADB find is unlocked, it can get canceled by
  other means removing it from the adbname list which in turn causes
  assertion failure due to a double removal from the adbname list. This
  has been fixed. :gl:`#5024` :gl:`!9722`

- Improve the memory cleaning in the SERVFAIL cache. ``5b96cbea01``

  The SERVFAIL cache doesn't have a memory bound and the cleaning of the
  old SERVFAIL cache entries was implemented only in opportunistic
  manner.  Improve the memory cleaning of the SERVFAIL cache to be more
  aggressive, so it doesn't consume a lot of memory in the case the
  server encounters many SERVFAILs at once. :gl:`#5025` :gl:`!9760`

- Fix trying the next primary server when the preivous one was marked as
  unreachable. ``025677943d``

  In some cases (there is evidence only when XoT was used) `named`
  failed to try the next primary server in the list when the previous
  one was marked as unreachable. This has been fixed. :gl:`#5038`
  :gl:`!9781`

- Clean up 'nodetach' in ns_client. ``617381f115``

  The 'nodetach' member is a leftover from the times when non-zero
  'stale-answer-client-timeout' values were supported, and currently is
  always 'false'. Clean up the member and its usage. :gl:`!9592`

- Enforce type checking for dns_dbnode_t. ``4b47c4f628``

  Originally, the dns_dbnode_t was typedef'ed to void type.  This
  allowed some flexibility, but using `(void *)` just removes any
  type-checking that C might have.  Instead of using:

  typedef void dns_dbnode_t;

  use a trick to define the type to non-existing structure:

  typedef struct dns_dbnode dns_dbnode_t;

  This allows the C compilers to employ the type-checking while the
  structure itself doesn't have to be ever defined because the actual
  'storage' is never accessed using dns_dbnode_t type. :gl:`!9719`

- Fix error path bugs in the manager's "recursing-clients" list
  management. ``508f7007e8``

  In two places, after linking the client to the manager's
  "recursing-clients" list using the check_recursionquota() function,
  the query.c module fails to unlink it on error paths. Fix the bugs by
  unlinking the client from the list. :gl:`!9586`


