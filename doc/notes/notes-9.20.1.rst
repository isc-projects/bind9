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
  :gl:`!9282`

- Implement rndc retransfer -force.

  A new optional argument '-force' has been added to the command channel
  command 'rndc retransfer'. When it is specified, named aborts the
  ongoing zone transfer (if there is one), and starts a new transfer.
  :gl:`#2299` :gl:`!9219`

Feature Changes
~~~~~~~~~~~~~~~

- Allow shorter resolver-query-timeout configuration.

  The minimum allowed value of 'resolver-query-timeout' was lowered to
  301 milliseconds instead of the earlier 10000 milliseconds (which is
  the default). As earlier, values less than or equal to 300 are
  converted to seconds before applying the limit. :gl:`#4320`
  :gl:`!9220`

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
  exceptions.  Dig was not reporting this. :gl:`#4808` :gl:`!9269`

- Fix assertion failure in the glue cache.

  Fix an assertion failure that could happen as a result of data race
  between free_gluetable() and addglue() on the same headers.
  :gl:`#4691` :gl:`!9256`

- Raise the log level of priming failures.

  When a priming query is complete, it's currently logged at level
  ISC_LOG_DEBUG(1), regardless of success or failure. We are now raising
  it to ISC_LOG_NOTICE in the case of failure. [GL #3516] :gl:`#3516`
  :gl:`!9250`

- Fix assertion failure when checking named-checkconf version.

  Checking the version of `named-checkconf` would end with assertion
  failure.  This has been fixed. :gl:`#4827` :gl:`!9246`

- Valid TSIG signatures with invalid time cause crash.

  An assertion failure triggers when the TSIG has valid cryptographic
  signature, but the time is invalid. This can happen when the times
  between the primary and secondary servers are not synchronised.
  :gl:`#4811` :gl:`!9245`

- Remove extra newline from yaml output.

  I split this into two commits, one for the actual newline removal, and
  one for issues I found, ruining the yaml output when some errors were
  outputted.

- Fix generation of 6to4-self name expansion from IPv4 address.

  The period between the most significant nibble of the encoded IPv4
  address and the 2.0.0.2.IP6.ARPA suffix was missing resulting in the
  wrong name being checked. Add system test for 6to4-self
  implementation. :gl:`#4766` :gl:`!9217`

- Fix false QNAME minimisation error being reported.

  Remove the false positive "success resolving" log message when QNAME
  minimisation is in effect and the final result is NXDOMAIN.
  :gl:`#4784` :gl:`!9215`

- Dig +yaml was producing unexpected and/or invalid YAML output.

  :gl:`#4796` :gl:`!9213`

- SVBC alpn text parsing failed to reject zero length alpn.

  :gl:`#4775` :gl:`!9209`

- Return SERVFAIL for a too long CNAME chain.

  When cutting a long CNAME chain, named was returning NOERROR  instead
  of SERVFAIL (alongside with a partial answer). This has been fixed.
  :gl:`#4449` :gl:`!9203`

- Properly calculate the amount of system memory.

  On 32 bit machines isc_meminfo_totalphys could return an incorrect
  value. :gl:`#4799` :gl:`!9199`

- Update key lifetime and metadata after dnssec-policy reconfig.

  Adjust key state and timing metadata if dnssec-policy key lifetime
  configuration is updated, so that it also affects existing keys.
  :gl:`#4677` :gl:`!9191`
