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

Notes for BIND 9.18.31
----------------------

New Features
~~~~~~~~~~~~

- Added WALLET type.

  Add the new record type WALLET (262).  This provides a mapping from a
  domain name to a cryptographic currency wallet.  Multiple mappings can
  exist if multiple records exist. :gl:`#4947`

Feature Changes
~~~~~~~~~~~~~~~

- Allow IXFR-to-AXFR fallback on ``DNS_R_TOOMANYRECORDS``.

  This change allows fallback from an IXFR failure to AXFR when the
  reason is ``DNS_R_TOOMANYRECORDS``. :gl:`#4928`

Bug Fixes
~~~~~~~~~

- Fix a statistics channel counter bug when "forward only" zones are
  used.

  When resolving a zone with a "forward only" policy, and finding out
  that all the forwarders were marked as "bad", the "ServerQuota"
  counter of the statistics channel was incorrectly increased. This has
  been fixed. :gl:`#1793`

- Fix a bug in the static-stub implementation.

  Static-stub addresses and addresses from other sources were being
  mixed together, resulting in static-stub queries going to addresses
  not specified in the configuration, or alternatively, static-stub
  addresses being used instead of the correct server addresses.
  :gl:`#4850`

- Don't allow :any:`statistics-channels` if libxml2 and libjson-c are
  not configured.

  When BIND 9 is not configured with the libxml2 and libjson-c
  libraries, the use of the :any:`statistics-channels` option is a fatal
  error.  :gl:`#4895`

- Limit the outgoing UDP send queue size.

  If the operating system UDP queue got full and the outgoing UDP
  sending started to be delayed, BIND 9 could exhibit memory spikes as
  it tried to enqueue all the outgoing UDP messages. It now tries to
  deliver the outgoing UDP messages synchronously; if that fails, it
  drops the outgoing DNS message that would get queued up and then
  timeout on the client side. :gl:`#4930`

- Do not set ``SO_INCOMING_CPU``.

  Remove the ``SO_INCOMING_CPU`` setting as kernel scheduling performs
  better without constraints. :gl:`#4936`


Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
