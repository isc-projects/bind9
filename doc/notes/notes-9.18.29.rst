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
  :gl:`!9283`

Bug Fixes
~~~~~~~~~

- Reconfigure catz member zones during named reconfiguration.

  During a reconfiguration named wasn't reconfiguring catalog zones'
  member zones. This has been fixed. :gl:`#4733`

- Raise the log level of priming failures.

  When a priming query is complete, it's currently logged at level
  ISC_LOG_DEBUG(1), regardless of success or failure. We are now raising
  it to ISC_LOG_NOTICE in the case of failure. [GL #3516] :gl:`#3516`
  :gl:`!9251`

- Add a compatibility shim for older libuv versions (< 1.19.0)

  The uv_stream_get_write_queue_size() is supported only in relatively
  newer versions of libuv (1.19.0 or higher).  Provide a compatibility
  shim for this function , so BIND 9 can be built in environments with
  older libuv version.

- Remove extra newline from yaml output.

  I split this into two commits, one for the actual newline removal, and
  one for issues I found, ruining the yaml output when some errors were
  outputted.

- Fix generation of 6to4-self name expansion from IPv4 address.

  The period between the most significant nibble of the encoded IPv4
  address and the 2.0.0.2.IP6.ARPA suffix was missing resulting in the
  wrong name being checked. Add system test for 6to4-self
  implementation. :gl:`#4766` :gl:`!9218`

- Fix false QNAME minimisation error being reported.

  Remove the false positive "success resolving" log message when QNAME
  minimisation is in effect and the final result is NXDOMAIN.
  :gl:`#4784` :gl:`!9216`

- Dig +yaml was producing unexpected and/or invalid YAML output.

  :gl:`#4796` :gl:`!9214`

- SVBC alpn text parsing failed to reject zero length alpn.

  :gl:`#4775` :gl:`!9210`

- Return SERVFAIL for a too long CNAME chain.

  When cutting a long CNAME chain, named was returning NOERROR  instead
  of SERVFAIL (alongside with a partial answer). This has been fixed.
  :gl:`#4449` :gl:`!9204`

- Properly calculate the amount of system memory.

  On 32 bit machines isc_meminfo_totalphys could return an incorrect
  value. :gl:`#4799` :gl:`!9200`

- Update key lifetime and metadata after dnssec-policy reconfig.

  Adjust key state and timing metadata if dnssec-policy key lifetime
  configuration is updated, so that it also affects existing keys.
  :gl:`#4677` :gl:`!9192`

- Fix dig +timeout argument when using +https.

  The +timeout argument was not used on DoH connections. This has been
  fixed.  :gl:`#4806` :gl:`!9161`


