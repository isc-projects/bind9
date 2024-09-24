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

BIND 9.21.0
-----------

New Features
~~~~~~~~~~~~

- Tighten 'max-recursion-queries' and add 'max-query-restarts' option.
  ``f202937078f``

  There were cases in resolver.c when the `max-recursion-queries` quota
  was ineffective. It was possible to craft zones that would cause a
  resolver to waste resources by sending excessive queries while
  attempting to resolve a name. This has been addressed by correcting
  errors in the implementation of `max-recursion-queries`, and by
  reducing the default value from 100 to 32.

  In addition, a new `max-query-restarts` option has been added which
  limits the number of times a recursive server will follow CNAME or
  DNAME records before terminating resolution. This was previously a
  hard-coded limit of 16, and now defaults to 11.   :gl:`#4741`
  :gl:`!9281`

- Implement rndc retransfer -force. ``34589811c59``

  A new optional argument '-force' has been added to the command channel
  command 'rndc retransfer'. When it is specified, named aborts the
  ongoing zone transfer (if there is one), and starts a new transfer.
  :gl:`#2299` :gl:`!9102`

- Add support for external log rotation tools. ``5ff1fbe1550``

  Add two mechanisms to close open log files.  The first is `rndc
  closelogs`.  The second is `kill -USR1 <pid>`. They are intended to be
  used with external log rotation tools. :gl:`#4780` :gl:`!9113`

- Generate changelog from git log. ``a64ecc5fdd8``

  Use a single source of truth, the git log, to generate the list of
  CHANGES. Use the .rst format and include it in the ARM for a quick
  reference with proper gitlab links to issues and merge requests.
  :gl:`#75` :gl:`!9152`

Feature Changes
~~~~~~~~~~~~~~~

- Use only c23 or c11 noreturn specifiers. ``cd92a145a36``

  Use `[[noreturn]]` when compiling with C23 or greater.

  The attribute macro name has been capitalized as `NORETURN` as
  defining it as `noreturn` breaks external headers. `#define noreturn
  __attribute__((noreturn))` wasn't used as C11's
  `stdnoreturn.h`/`_Noreturn` is required to build BIND9 in the first
  place. :gl:`!9149`

- Initialize the DST subsystem implicitly. ``7f2513a5aa8``

  Instead of calling dst_lib_init() and dst_lib_destroy() explicitly by
  all the programs, create a separate memory context for the DST
  subsystem and use the library constructor and destructor to initialize
  the DST internals. :gl:`!9254`

- Remove OpenSSL 1.x Engine support. ``b620b7e9118``

  The OpenSSL 1.x Engines support has been deprecated in the OpenSSL 3.x
  and is going to be removed from the upstream OpenSSL.  Remove the
  OpenSSL Engine support from BIND 9 in favor of OpenSSL 3.x Providers.
  :gl:`#4828` :gl:`!9252`

- Fix the rsa exponent to 65537. ``5fafb0e7f7b``

  There isn't a realistic reason to ever use e = 4294967297. Fortunately
  its codepath wasn't reachable to users and can be safetly removed.

  Keep in mind the `dns_key_generate` header comment was outdated. e = 3
  hasn't been used since 2006 so there isn't a reason to panic. The
  toggle was the public exponents between 65537 and 4294967297.
  :gl:`!9133`

- Remove the crc64 implementation. ``9397251eb32``

  CRC-64 has been added for map files. Now that the map file format has
  been removed, there isn't a reason to keep the implementation.
  :gl:`!9135`

- Call rcu_barrier() in the isc_mem_destroy() just once. ``dcee04f70cb``

  The previous work in this area was led by the belief that we might be
  calling call_rcu() from within call_rcu() callbacks.  After carefully
  checking all the current callback, it became evident that this is not
  the case and the problem isn't enough rcu_barrier() calls, but
  something entirely else.

  Call the rcu_barrier() just once as that's enough and the multiple
  rcu_barrier() calls will not hide the real problem anymore, so we can
  find it. :gl:`!9134`

- Require at least OpenSSL 1.1.1. ``96ccd962b72``

  OpenSSL 1.1.1 or better (or equivalent LibreSSL version) is now
  required to compile BIND 9. :gl:`#2806` :gl:`!9110`

- Don't open route socket if we don't need it. ``246d5ccbc9c``

  When automatic-interface-scan is disabled, the route socket was still
  being opened.  Add new API to connect / disconnect from the route
  socket only as needed.

  Additionally, move the block that disables periodic interface rescans
  to a place where it actually have access to the configuration values.
  Previously, the values were being checked before the configuration was
  loaded. :gl:`#4757` :gl:`!9122`

- Clarify that cds_wfcq_dequeue_blocking() doesn't block if empty.
  ``afe406be395``

  :gl:`!9124`

- Allow shorter resolver-query-timeout configuration. ``1661278b343``

  The minimum allowed value of 'resolver-query-timeout' was lowered to
  301 milliseconds instead of the earlier 10000 milliseconds (which is
  the default). As earlier, values less than or equal to 300 are
  converted to seconds before applying the limit. :gl:`#4320`
  :gl:`!9091`

- Replace `#define DNS_GETDB_` with struct of bools. ``020fda92b4b``

  Replace `#define DNS_GETDB_` with struct of bools to make it easier to
  pretty-print the attributes in a debugger. :gl:`#4559` :gl:`!9093`

- Fix data race in clean_finds_at_name. ``0dcc93d87a8``

  Stop updating `find.result_v4` and `find.result_v4` in
  `clean_finds_at_name`. The values are supposed to be
  static. :gl:`#4118` :gl:`!9108`

Bug Fixes
~~~~~~~~~

- Reconfigure catz member zones during named reconfiguration.
  ``acfa5b28f91``

  During a reconfiguration named wasn't reconfiguring catalog zones'
  member zones. This has been fixed. :gl:`#4733`

- Move the dst__openssl_toresult to isc_tls unit. ``9e7cd68d9fe``

  Since the enable_fips_mode() now resides inside the isc_tls unit, BIND
  9 would fail to compile when FIPS mode was enabled as the DST
  subsystem logging functions were missing.

  Move the crypto library logging functions from the openssl_link unit
  to isc_tls unit and enhance it, so it can now be used from both places
  keeping the old dst__openssl_toresult* macros alive. :gl:`!9286`

- Disassociate the SSL object from the cached SSL_SESSION.
  ``1d1bc3a1485``

  When the SSL object was destroyed, it would invalidate all SSL_SESSION
  objects including the cached, but not yet used, TLS session objects.

  Properly disassociate the SSL object from the SSL_SESSION before we
  store it in the TLS session cache, so we can later destroy it without
  invalidating the cached TLS sessions. :gl:`#4834` :gl:`!9271`

- Attach/detach to the listening child socket when accepting TLS.
  ``ee00bddf94f``

  When TLS connection (TLSstream) connection was accepted, the children
  listening socket was not attached to sock->server and thus it could
  have been freed before all the accepted connections were actually
  closed.

  In turn, this would cause us to call isc_tls_free() too soon - causing
  cascade errors in pending SSL_read_ex() in the accepted connections.

  Properly attach and detach the children listening socket when
  accepting and closing the server connections. :gl:`#4833` :gl:`!9270`

- Fix --enable-tracing build on systems without dtrace. ``ced1eb358da``

  Missing file util/dtrace.sh prevented builds on system without dtrace
  utility. This has been corrected.

- Make hypothesis optional for system tests. ``5dd3c416760``

  Ensure that system tests can be executed without Python hypothesis
  package. :gl:`#4831` :gl:`!9265`

- Dig now reports missing query section for opcode QUERY.
  ``7facf967aca``

  Query responses should contain the question section with some
  exceptions.  Dig was not reporting this. :gl:`#4808` :gl:`!9233`

- Fix assertion failure in the glue cache. ``227add4c3eb``

  Fix an assertion failure that could happen as a result of data race
  between free_gluetable() and addglue() on the same headers.
  :gl:`#4691` :gl:`!9126`

- Don't use 'create' flag unnecessarily in findnode() ``a26055f03ec``

  when searching the cache for a node so that we can delete an rdataset,
  it isn't necessary to set the 'create' flag. if the node doesn't exist
  yet, we won't be able to delete anything from it anyway. :gl:`!9158`

- Raise the log level of priming failures. ``6573276bada``

  When a priming query is complete, it's currently logged at level
  ISC_LOG_DEBUG(1), regardless of success or failure. We are now raising
  it to ISC_LOG_NOTICE in the case of failure. [GL #3516] :gl:`#3516`
  :gl:`!9121`

- Fix assertion failure when checking named-checkconf version.
  ``00739e99f67``

  Checking the version of `named-checkconf` would end with assertion
  failure.  This has been fixed. :gl:`#4827` :gl:`!9243`

- Valid TSIG signatures with invalid time cause crash. ``7a705a3ea4e``

  An assertion failure triggers when the TSIG has valid cryptographic
  signature, but the time is invalid. This can happen when the times
  between the primary and secondary servers are not synchronised.
  :gl:`#4811` :gl:`!9234`

- Don't skip the counting if fcount_incr() is called with force==true.
  ``026024a6aed``

  The fcount_incr() was incorrectly skipping the accounting for the
  fetches-per-zone if the force argument was set to true.  We want to
  skip the accounting only when the fetches-per-zone is completely
  disabled, but for individual names we need to do the accounting even
  if we are forcing the result to be success. :gl:`#4786` :gl:`!9115`

- Don't skip the counting if fcount_incr() is called with force==true
  (v2) ``8b70722fcb``

  The fcount_incr() was not increasing counter->count when force was set
  to true, but fcount_decr() would try to decrease the counter leading
  to underflow and assertion failure.  Swap the order of the arguments
  in the condition, so the !force is evaluated after incrementing the
  .count. :gl:`#4846` :gl:`!9298`

- Remove superfluous memset() in isc_nmsocket_init() ``4c363393ff1``

  The tlsstream part of the isc_nmsocket_t gets initialized via
  designater initializer and doesn't need the extra memset() later; just
  remove it. :gl:`!9120`

- Fix PTHREAD_MUTEX_ADAPTIVE_NP and PTHREAD_MUTEX_ERRORCHECK_NP usage.
  ``4efdb8b00a0``

  The PTHREAD_MUTEX_ADAPTIVE_NP and PTHREAD_MUTEX_ERRORCHECK_NP are
  usually not defines, but enum values, so simple preprocessor check
  doesn't work.

  Check for PTHREAD_MUTEX_ADAPTIVE_NP from the autoconf
  AS_COMPILE_IFELSE block and define HAVE_PTHREAD_MUTEX_ADAPTIVE_NP.
  This should enable adaptive mutex on Linux and FreeBSD.

  As PTHREAD_MUTEX_ERRORCHECK actually comes from POSIX and Linux glibc
  does define it when compatibility macros are being set, we can just
  use PTHREAD_MUTEX_ERRORCHECK instead of PTHREAD_MUTEX_ERRORCHECK_NP.
  :gl:`!9111`

- Remove extra newline from yaml output. ``b9cbd3bc767``

  I split this into two commits, one for the actual newline removal, and
  one for issues I found, ruining the yaml output when some errors were
  outputted.

- CID 498025 and CID 498031: Overflowed constant INTEGER_OVERFLOW.
  ``35d93624a56``

  Add INSIST to fail if the multiplication would cause the variables to
  overflow. :gl:`#4798` :gl:`!9131`

- Remove unnecessary operations. ``33f4ee7c36c``

  Decrementing optlen immediately before calling continue is unneccesary
  and inconsistent with the rest of dns_message_pseudosectiontoyaml and
  dns_message_pseudosectiontotext.  Coverity was also reporting an
  impossible false positive overflow of optlen (CID 499061). :gl:`!9130`

- Fix generation of 6to4-self name expansion from IPv4 address.
  ``ea2a5909a56``

  The period between the most significant nibble of the encoded IPv4
  address and the 2.0.0.2.IP6.ARPA suffix was missing resulting in the
  wrong name being checked. Add system test for 6to4-self
  implementation. :gl:`#4766` :gl:`!9099`

- Fix false QNAME minimisation error being reported. ``5857a4d3972``

  Remove the false positive "success resolving" log message when QNAME
  minimisation is in effect and the final result is NXDOMAIN.
  :gl:`#4784` :gl:`!9117`

- Dig +yaml was producing unexpected and/or invalid YAML output.
  ``93d7d221bd9``

  :gl:`#4796` :gl:`!9127`

- SVBC alpn text parsing failed to reject zero length alpn.
  ``0b56763df3f``

  :gl:`#4775` :gl:`!9106`

- Return SERVFAIL for a too long CNAME chain. ``89ab9e948d1``

  When cutting a long CNAME chain, named was returning NOERROR  instead
  of SERVFAIL (alongside with a partial answer). This has been fixed.
  :gl:`#4449` :gl:`!9090`

- Properly calculate the amount of system memory. ``6427d625ea5``

  On 32 bit machines isc_meminfo_totalphys could return an incorrect
  value. :gl:`#4799` :gl:`!9132`

- Update key lifetime and metadata after dnssec-policy reconfig.
  ``d9d882816aa``

  Adjust key state and timing metadata if dnssec-policy key lifetime
  configuration is updated, so that it also affects existing keys.
  :gl:`#4677` :gl:`!9118`

