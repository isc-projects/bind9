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

(-dev)
------

New Features
~~~~~~~~~~~~

- Tighten 'max-recursion-queries' and add 'max-query-restarts' option.

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

- Implement rndc retransfer -force.

  A new optional argument '-force' has been added to the command channel
  command 'rndc retransfer'. When it is specified, named aborts the
  ongoing zone transfer (if there is one), and starts a new transfer.
  :gl:`#2299` :gl:`!9102`

- Add support for external log rotation tools.

  Add two mechanisms to close open log files.  The first is `rndc
  closelogs`.  The second is `kill -USR1 <pid>`. They are intended to be
  used with external log rotation tools. :gl:`#4780` :gl:`!9113`

Feature Changes
~~~~~~~~~~~~~~~

- Remove OpenSSL 1.x Engine support.

  The OpenSSL 1.x Engines support has been deprecated in the OpenSSL 3.x
  and is going to be removed from the upstream OpenSSL.  Remove the
  OpenSSL Engine support from BIND 9 in favor of OpenSSL 3.x Providers.
  :gl:`#4828` :gl:`!9252`

- Require at least OpenSSL 1.1.1.

  OpenSSL 1.1.1 or better (or equivalent LibreSSL version) is now
  required to compile BIND 9. :gl:`#2806` :gl:`!9110`

- Allow shorter resolver-query-timeout configuration.

  The minimum allowed value of 'resolver-query-timeout' was lowered to
  301 milliseconds instead of the earlier 10000 milliseconds (which is
  the default). As earlier, values less than or equal to 300 are
  converted to seconds before applying the limit. :gl:`#4320`
  :gl:`!9091`

Bug Fixes
~~~~~~~~~

- Reconfigure catz member zones during named reconfiguration.

  During a reconfiguration named wasn't reconfiguring catalog zones'
  member zones. This has been fixed. :gl:`#4733`

- Fix --enable-tracing build on systems without dtrace.

  Missing file util/dtrace.sh prevented builds on system without dtrace
  utility. This has been corrected.

- Dig now reports missing query section for opcode QUERY.

  Query responses should contain the question section with some
  exceptions.  Dig was not reporting this. :gl:`#4808` :gl:`!9233`

- Fix assertion failure in the glue cache.

  Fix an assertion failure that could happen as a result of data race
  between free_gluetable() and addglue() on the same headers.
  :gl:`#4691` :gl:`!9126`

- Raise the log level of priming failures.

  When a priming query is complete, it's currently logged at level
  ISC_LOG_DEBUG(1), regardless of success or failure. We are now raising
  it to ISC_LOG_NOTICE in the case of failure. [GL #3516] :gl:`#3516`
  :gl:`!9121`

- Fix assertion failure when checking named-checkconf version.

  Checking the version of `named-checkconf` would end with assertion
  failure.  This has been fixed. :gl:`#4827` :gl:`!9243`

- Valid TSIG signatures with invalid time cause crash.

  An assertion failure triggers when the TSIG has valid cryptographic
  signature, but the time is invalid. This can happen when the times
  between the primary and secondary servers are not synchronised.
  :gl:`#4811` :gl:`!9234`

- Remove extra newline from yaml output.

  I split this into two commits, one for the actual newline removal, and
  one for issues I found, ruining the yaml output when some errors were
  outputted.

- Fix generation of 6to4-self name expansion from IPv4 address.

  The period between the most significant nibble of the encoded IPv4
  address and the 2.0.0.2.IP6.ARPA suffix was missing resulting in the
  wrong name being checked. Add system test for 6to4-self
  implementation. :gl:`#4766` :gl:`!9099`

- Fix false QNAME minimisation error being reported.

  Remove the false positive "success resolving" log message when QNAME
  minimisation is in effect and the final result is NXDOMAIN.
  :gl:`#4784` :gl:`!9117`

- Dig +yaml was producing unexpected and/or invalid YAML output.

  :gl:`#4796` :gl:`!9127`

- SVBC alpn text parsing failed to reject zero length alpn.

  :gl:`#4775` :gl:`!9106`

- Return SERVFAIL for a too long CNAME chain.

  When cutting a long CNAME chain, named was returning NOERROR  instead
  of SERVFAIL (alongside with a partial answer). This has been fixed.
  :gl:`#4449` :gl:`!9090`

- Properly calculate the amount of system memory.

  On 32 bit machines isc_meminfo_totalphys could return an incorrect
  value. :gl:`#4799` :gl:`!9132`

- Update key lifetime and metadata after dnssec-policy reconfig.

  Adjust key state and timing metadata if dnssec-policy key lifetime
  configuration is updated, so that it also affects existing keys.
  :gl:`#4677` :gl:`!9118`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
