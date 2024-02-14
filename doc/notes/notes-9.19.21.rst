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

Notes for BIND 9.19.21
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Validating DNS messages containing a lot of DNSSEC signatures could
  cause excessive CPU load, leading to a denial-of-service condition.
  This has been fixed. :cve:`2023-50387`

  ISC would like to thank Elias Heftrig, Haya Schulmann, Niklas Vogel,
  and Michael Waidner from the German National Research Center for
  Applied Cybersecurity ATHENE for bringing this vulnerability to our
  attention. :gl:`#4424`

- Preparing an NSEC3 closest encloser proof could cause excessive CPU
  load, leading to a denial-of-service condition. This has been fixed.
  :cve:`2023-50868` :gl:`#4459`

- Parsing DNS messages with many different names could cause excessive
  CPU load. This has been fixed. :cve:`2023-4408`

  ISC would like to thank Shoham Danino from Reichman University, Anat
  Bremler-Barr from Tel-Aviv University, Yehuda Afek from Tel-Aviv
  University, and Yuval Shavitt from Tel-Aviv University for bringing
  this vulnerability to our attention. :gl:`#4234`

- Specific queries could cause :iscman:`named` to crash with an
  assertion failure when :any:`nxdomain-redirect` was enabled. This has
  been fixed. :cve:`2023-5517` :gl:`#4281`

- A bad interaction between DNS64 and serve-stale could cause
  :iscman:`named` to crash with an assertion failure, when both of these
  features were enabled. This has been fixed. :cve:`2023-5679`
  :gl:`#4334`

Feature Changes
~~~~~~~~~~~~~~~

- :iscman:`named-compilezone` no longer performs zone integrity checks
  by default; this allows faster conversion of a zone file from one
  format to another. :gl:`#4364`

  Zone checks can be performed by running :iscman:`named-checkzone`
  separately, or the previous default behavior can be restored by using:

  ::

    named-compilezone -i full -k fail -n fail -r warn -m warn -M warn -S warn -T warn -W warn -C check-svcb:fail

Bug Fixes
~~~~~~~~~

- The counters exported via the statistics channel were changed back to
  64-bit signed values; they were being inadvertently truncated to
  unsigned 32-bit values since BIND 9.15.0. :gl:`#4467`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
