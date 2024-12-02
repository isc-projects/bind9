Notes for BIND 9.21.3
---------------------

New Features
~~~~~~~~~~~~

- Add separate query counters for new protocols.

  Add query counters for DoT, DoH, unencrypted DoH and their proxied
  counterparts. The new protocols do not update their respective TCP/UDP
  transport counter and is now for TCP/UDP over plain 53 only.
  :gl:`#598`

- Implement RFC 9567: EDNS Report-Channel option.

  Add new `send-report-channel` and `log-report-channel` options.
  `send-report-channel` specifies an agent domain, to which error
  reports can be sent by querying a specially constructed name within
  the agent domain. EDNS Report-Channel options will be added to
  outgoing authoritative responses, to inform clients where to send such
  queries in the event of a problem.

  If a zone is configured which matches the agent domain and has
  `log-report-channel` set to `yes`, error-reporting queries will be
  logged at level `info` to the `dns-reporting-agent` logging channel.
  :gl:`#3659`

- Add detailed debugging of update-policy rule matching.

  This logs how named determines if an update request is granted or
  denied when using update-policy. :gl:`#4751`

- Update bind.keys with the new 2025 IANA root key.

  Add an 'initial-ds' entry to bind.keys for the new root key, ID 38696,
  which is scheduled for publication in January 2025. :gl:`#4896`

- Enable runtime selection of FIPS mode in dig and delv.

  'dig -F' and 'delv -F' can now be used to select FIPS mode at runtime.
  :gl:`#5046`

Removed Features
~~~~~~~~~~~~~~~~

- Move contributed DLZ modules into a separate repository.

  The DLZ modules are poorly maintained as we only ensure they can still
  be compiled, the DLZ interface is blocking, so anything that blocks
  the query to the database blocks the whole server and they should not
  be used except in testing.  The DLZ interface itself is going to be
  scheduled for removal.

  The DLZ modules now live in
  https://gitlab.isc.org/isc-projects/dlz-modules repository.
  :gl:`#4865`

- Remove RBTDB implementation.

  Remove the RBTDB database implementation, and only leave the QPDB
  based implementations of zone and cache databases.  This means it's no
  longer possible to choose the RBTDB to be default at the compilation
  time and it's not possible to configure RBTDB as the database backend
  in the configuration file. :gl:`#5027`

Feature Changes
~~~~~~~~~~~~~~~

- Dnssec-ksr now supports KSK rollovers.

  The tool 'dnssec-ksr' now allows for KSK generation, as well as
  planned KSK rollovers. When signing a bundle from a Key Signing
  Request (KSR), only the key that is active in that time frame is being
  used for signing. Also, the CDS and CDNSKEY records are now added and
  removed at the correct time. :gl:`#4697`  :gl:`#4705`

- Add none parameter to query-source and query-source-v6 to disable IPv4
  or IPv6 upstream queries.

  Add a none parameter to named configuration option `query-source`
  (respectively `query-source-v6`) which forbid usage of IPv4
  (respectively IPv6) addresses when named is doing an upstream query.
  :gl:`#4981` Turning-off upstream IPv6 queries while still listening to
  downstream queries on IPv6.

- Print expire option in transfer summary.

  The zone transfer summary will now print the expire option value in
  the zone transfer summary. :gl:`#5013`

- Add missing EDNS option mnemonics.

  The `Report-Channel` and `ZONEVERSION` EDNS options can now be sent
  using `dig +ednsopt=report-channel` (or `dig +ednsopt=rc` for short),
  and `dig +ednsopt=zoneversion`.

  Several other EDNS option names, including `DAU`, `DHU`, `N3U`, and
  `CHAIN`, are now displayed correctly in text and YAML formats. Also,
  an inconsistency has been corrected: the `TCP-KEEPALIVE` option is now
  spelled with a hyphen in both text and YAML formats; previously, text
  format used a space.

- Add new logging module for logging crypto errors in libisc.

  Add a new 'crypto' log module that will be used for a low-level
  cryptographic operations.  The DNS related cryptography logs are still
  logged in the 'dns/crypto' module.

- Emit more helpful log for exceeding max-records-per-type.

  The new log message is emitted when adding or updating an RRset fails
  due to exceeding the max-records-per-type limit. The log includes the
  owner name and type, corresponding zone name, and the limit value. It
  will be emitted on loading a zone file, inbound zone transfer (both
  AXFR and IXFR), handling a DDNS update, or updating a cache DB. It's
  especially helpful in the case of zone transfer, since the secondary
  side doesn't have direct access to the offending zone data.

  It could also be used for max-types-per-name, but this change doesn't
  implement it yet as it's much less likely to happen in practice.

- Harden key management when key files have become unavailabe.

  Prior to doing key management, BIND 9 will check if the key files on
  disk match the expected keys. If key files for previously observed
  keys have become unavailable, this will prevent the internal key
  manager from running.

Bug Fixes
~~~~~~~~~

- Use TLS for notifies if configured to do so.

  Notifies configured to use TLS will now be sent over TLS, instead of
  plaintext UDP or TCP. Also, failing to load the TLS configuration for
  notify now also results in an error. :gl:`#4821`

- '{&dns}' is as valid as '{?dns}' in a SVCB's dohpath.

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
  handle complex templates. :gl:`#4922`

- Fix NSEC3 closest encloser lookup for names with empty non-terminals.

  The performance improvement for finding the NSEC3 closest encloser
  when generating authoritative responses could cause servers to return
  incorrect NSEC3 records in some cases. This has been fixed.
  :gl:`#4950`

- Report client transport in 'rndc recursing'

  When `rndc recursing` is used to dump the list of recursing clients,
  it now indicates whether a query was sent via UDP, TCP, TLS, or HTTP.
  :gl:`#4971`

- 'Recursive-clients 0;' triggers an assertion.

  BIND 9.20.0 broke `recursive-clients 0;`.  This has now been fixed.
  :gl:`#4987`

- Parsing of hostnames in rndc.conf was broken.

  When DSCP support was removed, parsing of hostnames in rndc.conf was
  accidentally broken, resulting in an assertion failure.  This has been
  fixed. :gl:`#4991`

- Restore values when dig prints command line.

  Options of the form `[+-]option=<value>` failed to display the value
  on the printed command line. This has been fixed. :gl:`#4993`

- Provide more visibility into configuration errors.

  by logging SSL_CTX_use_certificate_chain_file and
  SSL_CTX_use_PrivateKey_file errors individually. :gl:`#5008`

- Fix race condition when canceling ADB find.

  When canceling the ADB find, the lock on the find gets released for a
  brief period of time to be locked again inside adbname lock.  During
  the brief period that the ADB find is unlocked, it can get canceled by
  other means removing it from the adbname list which in turn causes
  assertion failure due to a double removal from the adbname list. This
  has been fixed. :gl:`#5024`

- Improve the memory cleaning in the SERVFAIL cache.

  The SERVFAIL cache doesn't have a memory bound and the cleaning of the
  old SERVFAIL cache entries was implemented only in opportunistic
  manner.  Improve the memory cleaning of the SERVFAIL cache to be more
  aggressive, so it doesn't consume a lot of memory in the case the
  server encounters many SERVFAILs at once. :gl:`#5025`

- Fix trying the next primary server when the preivous one was marked as
  unreachable.

  In some cases (there is evidence only when XoT was used) `named`
  failed to try the next primary server in the list when the previous
  one was marked as unreachable. This has been fixed. :gl:`#5038`


