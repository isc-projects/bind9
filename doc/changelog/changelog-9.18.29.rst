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

BIND 9.18.29
------------

New Features
~~~~~~~~~~~~

- Tighten 'max-recursion-queries' and add 'max-query-restarts' option.
  ``fe3ae71e90``

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

- Generate changelog from git log. ``21a0b6aef7``

  Use a single source of truth, the git log, to generate the list of
  CHANGES. Use the .rst format and include it in the ARM for a quick
  reference with proper gitlab links to issues and merge requests.
  :gl:`#75` :gl:`!9181`

Feature Changes
~~~~~~~~~~~~~~~

- Use _exit() in the fatal() function. ``e4c483f45f``

  Since the fatal() isn't a correct but rather abrupt termination of the
  program, we want to skip the various atexit() calls because not all
  memory might be freed during fatal() call, etc.  Using _exit() instead
  of exit() has this effect - the program will end, but no destructors
  or atexit routines will be called. :gl:`!9263`

- Fix data race in clean_finds_at_name. ``541726871d``

  Stop updating `find.result_v4` and `find.result_v4` in
  `clean_finds_at_name`. The values are supposed to be
  static. :gl:`#4118` :gl:`!9198`

Bug Fixes
~~~~~~~~~

- Reconfigure catz member zones during named reconfiguration.
  ``944d0dc942``

  During a reconfiguration named wasn't reconfiguring catalog zones'
  member zones. This has been fixed. :gl:`#4733`

- Disassociate the SSL object from the cached SSL_SESSION.
  ``64fde41253``

  When the SSL object was destroyed, it would invalidate all SSL_SESSION
  objects including the cached, but not yet used, TLS session objects.

  Properly disassociate the SSL object from the SSL_SESSION before we
  store it in the TLS session cache, so we can later destroy it without
  invalidating the cached TLS sessions. :gl:`#4834` :gl:`!9279`

- Attach/detach to the listening child socket when accepting TLS.
  ``3ead47daff``

  When TLS connection (TLSstream) connection was accepted, the children
  listening socket was not attached to sock->server and thus it could
  have been freed before all the accepted connections were actually
  closed.

  In turn, this would cause us to call isc_tls_free() too soon - causing
  cascade errors in pending SSL_read_ex() in the accepted connections.

  Properly attach and detach the children listening socket when
  accepting and closing the server connections. :gl:`#4833` :gl:`!9278`

- Make hypothesis optional for system tests. ``0d1953d7a8``

  Ensure that system tests can be executed without Python hypothesis
  package. :gl:`#4831` :gl:`!9268`

- Don't loop indefinitely when isc_task quantum is 'unlimited'
  ``674420df64``

  Don't run more events than already scheduled.  If the quantum is set
  to a high value, the task_run() would execute already scheduled, and
  all new events that result from running event->ev_action().

  Setting quantum to a number of scheduled events will postpone events
  scheduled after we enter the loop here to the next task_run()
  invocation. :gl:`!9257`

- Raise the log level of priming failures. ``c948babeeb``

  When a priming query is complete, it's currently logged at level
  ISC_LOG_DEBUG(1), regardless of success or failure. We are now raising
  it to ISC_LOG_NOTICE in the case of failure. [GL #3516] :gl:`#3516`
  :gl:`!9251`

- Add a compatibility shim for older libuv versions (< 1.19.0)
  ``61ff983f00``

  The uv_stream_get_write_queue_size() is supported only in relatively
  newer versions of libuv (1.19.0 or higher).  Provide a compatibility
  shim for this function , so BIND 9 can be built in environments with
  older libuv version.

- Remove extra newline from yaml output. ``1222dbe9f9``

  I split this into two commits, one for the actual newline removal, and
  one for issues I found, ruining the yaml output when some errors were
  outputted.

- CID 498025 and CID 498031: Overflowed constant INTEGER_OVERFLOW.
  ``bbdd888b8e``

  Add INSIST to fail if the multiplication would cause the variables to
  overflow. :gl:`#4798` :gl:`!9230`

- Remove unnecessary operations. ``2374a1a2bd``

  Decrementing optlen immediately before calling continue is unneccesary
  and inconsistent with the rest of dns_message_pseudosectiontoyaml and
  dns_message_pseudosectiontotext.  Coverity was also reporting an
  impossible false positive overflow of optlen (CID 499061). :gl:`!9224`

- Fix generation of 6to4-self name expansion from IPv4 address.
  ``df55c15ebb``

  The period between the most significant nibble of the encoded IPv4
  address and the 2.0.0.2.IP6.ARPA suffix was missing resulting in the
  wrong name being checked. Add system test for 6to4-self
  implementation. :gl:`#4766` :gl:`!9218`

- Fix false QNAME minimisation error being reported. ``4984afc80c``

  Remove the false positive "success resolving" log message when QNAME
  minimisation is in effect and the final result is NXDOMAIN.
  :gl:`#4784` :gl:`!9216`

- Dig +yaml was producing unexpected and/or invalid YAML output.
  ``2db62a4dba``

  :gl:`#4796` :gl:`!9214`

- SVBC alpn text parsing failed to reject zero length alpn.
  ``8f7be89052``

  :gl:`#4775` :gl:`!9210`

- Return SERVFAIL for a too long CNAME chain. ``f7de909b98``

  When cutting a long CNAME chain, named was returning NOERROR  instead
  of SERVFAIL (alongside with a partial answer). This has been fixed.
  :gl:`#4449` :gl:`!9204`

- Properly calculate the amount of system memory. ``9faf355a5c``

  On 32 bit machines isc_meminfo_totalphys could return an incorrect
  value. :gl:`#4799` :gl:`!9200`

- Update key lifetime and metadata after dnssec-policy reconfig.
  ``2107a64ee6``

  Adjust key state and timing metadata if dnssec-policy key lifetime
  configuration is updated, so that it also affects existing keys.
  :gl:`#4677` :gl:`!9192`

- Fix dig +timeout argument when using +https. ``381d6246d6``

  The +timeout argument was not used on DoH connections. This has been
  fixed.  :gl:`#4806` :gl:`!9161`
