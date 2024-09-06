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

Notes for BIND 9.21.1
---------------------

New Features
~~~~~~~~~~~~

- Support for Offline KSK implemented.

  Add a new configuration option `offline-ksk` to enable Offline KSK key
  management. Signed Key Response (SKR) files created with `dnssec-ksr`
  (or other program) can now be imported into `named` with the new `rndc
  skr -import` command. Rather than creating new DNSKEY, CDS and CDNSKEY
  records and generating signatures covering these types, these records
  are loaded from the currently active bundle from the imported SKR.

  The implementation is loosely based on:
  https://www.iana.org/dnssec/archive/files/draft-icann-dnssec-
  keymgmt-01.txt :gl:`#1128`

- Implement the 'request-ixfr-max-diffs' configuration option.

  The new 'request-ixfr-max-diffs' configuration option sets the maximum
  number of incoming incremental zone transfer (IXFR) differences,
  exceeding which triggers a full zone transfer (AXFR). :gl:`#4389`

- Print the full path of the working directory in startup log messages.

  named now prints its initial working directory during startup and the
  changed working directory when loading or reloading its configuration
  file if it has a valid 'directory' option defined. :gl:`#4731`

- Support restricted key tag range when generating new keys.

  It is useful when multiple signers are being used to sign a zone to
  able to specify a restricted range of range of key tags that will be
  used by an operator to sign the zone.  This adds controls to named
  (dnssec-policy), dnssec-signzone, dnssec-keyfromlabel and dnssec-ksr
  (dnssec-policy) to specify such ranges. :gl:`#4830`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the 'dialup' and 'heartbeat-interval' options.

  The `dialup` and `heartbeat-interval` options have been removed, along
  with all code implementing them. Using these options is now a fatal
  error. :gl:`#4237`

Feature Changes
~~~~~~~~~~~~~~~

- Use deterministic ecdsa for openssl >= 3.2.

  OpenSSL has added support for deterministic ECDSA (RFC 6979) with
  version 3.2.

  Use it by default as it removes arguably its most fragile side of
  ECDSA. The derandomization doesn't pose a risk for DNS usecases and is
  allowed by FIPS 186-5. :gl:`#299`

- Exempt prefetches from the fetches-per-zone and fetches-per-server
  quotas.

  Fetches generated automatically as a result of 'prefetch' are now
  exempt from the 'fetches-per-zone' and 'fetches-per-server' quotas.
  This should help in maintaining the cache from which query responses
  can be given. :gl:`#4219`

- Follow the number of CPU set by taskset/cpuset.

  Administrators may wish to constrain the set of cores that BIND 9 runs
  on via the 'taskset', 'cpuset' or 'numactl' programs (or equivalent on
  other O/S).

  If the admin has used taskset, the `named` will now follow to
  automatically use the given number of CPUs rather than the system wide
  count. :gl:`#4884`

Bug Fixes
~~~~~~~~~

- Delay release of root privileges until after configuring controls.

  Delay relinquishing root privileges until the control channel has been
  configured, for the benefit of systems that require root to use
  privileged port numbers.  This mostly affects systems without fine-
  grained privilege systems (i.e., other than Linux). :gl:`#4793`

- Fix rare assertion failure when shutting down incoming transfer.

  A very rare assertion failure can be triggered when the incoming
  transfer is either forcefully shut down or it is finished during
  printing the details about the statistics channel.  This has been
  fixed. :gl:`#4860`

- Fix algoritm rollover bug when there are two keys with the same
  keytag.

  If there is an algorithm rollover and two keys of different algorithm
  share the same keytags, then there is a possibility that if we check
  that a key matches a specific state, we are checking against the wrong
  key. This has been fixed by not only checking for matching key tag but
  also key algorithm. :gl:`#4878`

- Fix an assertion failure in validate_dnskey_dsset_done()

  Under rare circumstances, named could terminate unexpectedly when
  validating a DNSKEY resource record if the validation was canceled in
  the meantime. This has been fixed. :gl:`#4911`

Known Issues
~~~~~~~~~~~~

- Long-running tasks in offloaded threads (e.g. the loading of RPZ zones
  or processing zone transfers) may block the resolution of queries
  during these operations and cause the queries to time out.

  To work around the issue, the ``UV_THREADPOOL_SIZE`` environment
  variable can be set to a larger value before starting :iscman:`named`.
  The recommended value is the number of RPZ zones (or number of
  transfers) plus the number of threads BIND should use, which is
  typically the number of CPUs. :gl:`#4898`
