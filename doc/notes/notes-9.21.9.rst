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

Notes for BIND 9.21.9
---------------------

New Features
~~~~~~~~~~~~

- Add support for zone templates.

  To simplify the configuration of multiple similar zones, BIND 9 now
  supports a zone template mechanism. :namedconf:ref:`template` blocks
  containing zone options can be defined at the top level of the
  configuration file and then referenced in :namedconf:ref:`zone`
  statements. A zone referencing a template uses the options in the
  specified :namedconf:ref:`template` block as defaults. (Options
  locally defined in the zone statement override the template.)

  The filename for a zone can now be generated parametrically from a
  format specified in the :namedconf:ref:`file` option. The first
  occurrences of ``$name``, ``$type``, and ``$view`` in file are
  replaced with the zone origin, the zone type (i.e., primary,
  secondary, ...), and the view name, respectively.

  Primary zones can now take an :namedconf:ref:`initial-file` option,
  specifying the path to a generic zone file that are copied into the
  zone's file path when the zone is first loaded, if the file does not
  already exist.

  For example, the following template can be used for primary zones:

  ::


    template primary {
      type primary;
      file "$name.db";
      initial-file "generic.db";
    };

  With this template in place, a new primary zone could be added using a
  single :option:`rndc addzone` command:

  ::


    rndc addzone example.com '{ template primary; };'

  The zone would be created using the filename ``example.com.db``, which
  would be copied into place from ``generic.db``. :gl:`#2964`

- Redesign the unreachable primaries cache.

  Previously, the cache for the unreachable primary servers was limited
  to 10 entries (LRU) with a fixed 10-minute delay for each entry,
  unless removed forcibly by a new entry. The cache is now redesigned to
  remove the 10-entry limitation and to introduce delay values with an
  exponential backoff time: initially an unreachable primary server is
  cached as being unreachable for 10 seconds, but each time the cache
  entry is expired and the same server is added again during the
  eligibility period of the next 120 seconds, the delay time is doubled,
  up to the maximum of 640 seconds. :gl:`#3992`

- Implement a new :namedconf:ref:`notify-defer` configuration option.

  This new option sets a delay (in seconds) to wait before sending a set
  of ``NOTIFY`` messages for a zone. Whenever a ``NOTIFY`` message is
  ready to be sent, sending is deferred for this duration. This option
  should not be confused with the :namedconf:ref:`notify-delay` option.
  The default is 0 seconds. :gl:`#5259`

Bug Fixes
~~~~~~~~~

- Fix zone deletion issue.

  A secondary zone could initiate a new zone transfer from the primary
  server after it had been already deleted from the secondary server,
  and before the internal garbage collection was activated to clean it
  up completely. This has been fixed. :gl:`#5291`

- Fix a zone refresh bug.

  A secondary zone could fail to further refresh with new versions of
  the zone from a primary server if :iscman:`named` was reconfigured
  during the SOA request step of an ongoing zone transfer. This has been
  fixed.  :gl:`#5307`


