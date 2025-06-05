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

BIND 9.21.9
-----------

New Features
~~~~~~~~~~~~

- Add support for zone templates. ``93c44ba551c``

  To simplify the configuration of multiple similar zones, BIND now
  supports a zone template mechanism. `template` blocks containing zone
  options can be defined at the top level of the configuration file;
  they can then be referenced in `zone` statements. A zone referencing a
  template will use the options in the specified `template` block as
  defaults. (Options locally defined in the `zone` statement override
  the template.)

  The filename for a zone can now be generated parametrically from a
  format specified in the `file` option. The first occurrences of
  `$name`, `$type` and `$view` in `file` are replaced with the zone
  origin, the zone type (i.e., primary, secondary, etc), and the view
  name, respectively.

  Primary zones can now take an `initial-file` option, specifying the
  path to a generic zone file that will be copied into the zone's `file`
  path when the zone is first loaded, if the `file` does not already
  exist.

  For example, the following template can be used for primary zones: ```
  template primary {                 type primary;                 file
  "$name.db";                 initial-file "generic.db";         }; ```

  With this template in place, a new primary zone could be added using a
  single `rndc addzone` command:

  ```         $ rndc addzone example.com '{ template primary; };' ```

  The zone would be created using the filename `example.com.db`, which
  would be copied into place from `generic.db`. :gl:`#2964` :gl:`!10407`

- Redesign the unreachable primaries cache. ``b8144348362``

  Previously, the cache for the unreachable primary servers was limited
  to 10 entries (LRU) and a fixed 10 minutes delay for each entry,
  unless removed forcibly by a new entry. The cache is now redesigned to
  remove the 10 entry limitation and to introduce delay values with
  exponential backoff time - initially an unreachable primary server is
  cached as being unreachable for 10 seconds, but each time the cache
  entry is expired and the same server is added again during the
  eligibility period of the next 120 seconds, the delay time is doubled
  up until to the maximum of 640 seconds. :gl:`#3992` :gl:`!10393`

- Implement a new 'notify-defer' configuration option. ``10a02e84ebf``

  This new option sets a delay (in seconds) to wait before sending a set
  of NOTIFY messages for a zone. Whenever a NOTIFY message is ready to
  be sent, sending will be deferred for this duration. This option is
  not to be confused with the :any:`notify-delay` option. The default is
  0 seconds. :gl:`#5259` :gl:`!10419`

Removed Features
~~~~~~~~~~~~~~~~

- Clean up the DST cryptographic API. ``43f19763b32``

  The DST API has been cleaned up, duplicate functions has been squashed
  into single call (verify and verify2 functions), and couple of unused
  functions have been completely removed (createctx2, computesecret,
  paramcompare, and cleanup). :gl:`!10345`

Feature Changes
~~~~~~~~~~~~~~~

- Adaptive memory allocation strategy for qp-tries. ``dc3a1bde658``

  qp-tries allocate their nodes (twigs) in chunks to reduce allocator
  pressure and improve memory locality. The choice of chunk size
  presents a tradeoff: larger chunks benefit qp-tries with many values
  (as seen in large zones and resolvers) but waste memory in smaller use
  cases.

  Previously, our fixed chunk size of 2^10 twigs meant that even an
  empty qp-trie would consume 12KB of memory, while reducing this size
  would negatively impact resolver performance.

  This commit implements an adaptive chunking strategy that:  - Tracks
  the size of the most recently allocated chunk.  - Doubles the chunk
  size for each new allocation until reaching a    predefined maximum.

  This approach effectively balances memory efficiency for small tries
  while maintaining the performance benefits of larger chunk sizes for
  bigger data structures. :gl:`!10245`

- Set name for all the isc_mem context from isc_mem_create()
  ``ccf7a7dd7ea``

  Instead of giving the memory context names with an explicit call to
  isc_mem_setname(), add the name to isc_mem_create() call to have all
  the memory contexts an unconditional name. :gl:`!10426`

- Unify handling of the program name in all the utilities.
  ``33f17c23848``

  There were several methods how we used 'argv[0]'.  Some programs had a
  static value, some programs did use isc_file_progname(), some programs
  stripped 'lt-' from the beginning of the name.  And some used argv[0]
  directly.

  Unify the handling and all the variables into isc_commandline_progname
  that gets populated by the new isc_commandline_init(argc, argv) call.
  :gl:`!10502`

Bug Fixes
~~~~~~~~~

- Fix zone deletion issue. ``bc4a19acff7``

  A secondary zone could initiate a new zone transfer from the primary
  server after it had been already deleted from the secondary server,
  and before the internal garbage collection was activated to clean it
  up completely. This has been fixed. :gl:`#5291` :gl:`!10449`

- Fix a zone refresh bug. ``610825ebc14``

  A secondary zone could fail to further refresh with new versions of
  the zone from a primary server if named was reconfigured during the
  SOA request step of an ongoing zone transfer. This has been fixed.
  :gl:`#5307` :gl:`!10468`

- Allow keystore.c to compile on Solaris. ``9b7c19a3400``

  keystore.c failed to compile on Solaris because NAME_MAX was
  undefined.  Include 'isc/dir.h' which defines NAME_MAX for platforms
  that don't define it. :gl:`#5327` :gl:`!10522`

- Call zone syntax checks when running rndc addzone/modzone.
  ``2ad9516a72a``

  The function that checks zone syntax in libisccfg was previously only
  called when loading `named.conf`, not when parsing an an `rndc
  addzone` or `rndc modzone` command. This has been corrected.
  :gl:`#5338` :gl:`!10520`

- Add more iteration macros. ``a988ffcede7``

  Add more macros for iteration: `DNS_RDATASET_FOREACH`,
  `CFG_LIST_FOREACH`, `DNS_DBITERATOR_FOREACH`, and
  `DNS_RDATASETITER_FOREACH`. :gl:`!10350`

- Allow commandline.c to compile on Solaris. ``ead7b480034``

  commandline.c failed to compile on Solaris because NAME_MAX was
  undefined.  Include 'isc/dir.h' which defines NAME_MAX for platforms
  that don't define it.

  In file included from commandline.c:54:
  ./include/isc/commandline.h:31:38: error: 'NAME_MAX' undeclared here
  (not in a function)        31 | extern char
  isc_commandline_progname[NAME_MAX];           |
  ^~~~~~~~ :gl:`!10524`

- Debug level was ignored when logging to stderr. ``870c9b6a910``

  The debug level (set with the `-d` option) was ignored when running
  `named` with the `-g` and `-u` options. :gl:`!10453`

- Fix builds for the OSS-Fuzz project. ``bf6caadd676``

  Add the `size` argument to the fuzzing version of the
  `chunk_get_raw()` function. :gl:`!10553`

- Initialize queryonacl dns_view_t property. ``bb1458460b3``

  A dns_view_t has a queryonacl property, which is supposed to hold the
  ACL matching the configuration "allow-query-on". However the code
  parsing this configuration ACL was missing (or removed by mistake?),
  hence this property was always NULL. The ACL was still built but
  individually for each zone (which checks if the property exists in the
  zone definition, view definition, and finally options definition).

  We now create the ACL instance at the view level, enabling zones to
  share the same (identical) ACL instead of having their own copies.
  :gl:`!10551`

- Make all ISC_LIST_FOREACH calls safe. ``b045726f8f4``

  Previously, `ISC_LIST_FOREACH` and `ISC_LIST_FOREACH_SAFE` were two
  separate macros, with the _SAFE version allowing entries to be
  unlinked during the loop. `ISC_LIST_FOREACH` is now also safe, and the
  separate `_SAFE` macro has been removed.

  Similarly, the `ISC_LIST_FOREACH_REV` macro is now safe, and
  `ISC_LIST_FOREACH_REV_SAFE` has also been removed. :gl:`!10479`

- Set name for all the isc_mem contexts. ``87ad1624634``

  :gl:`!10425`

- Try to skip lock on fully lower names. ``59585e22947``

  If the name is fully lowercase, we don't need to access the case
  bitmap in order to set the case. Therefore, we can check for the
  FULLYLOWERCASE flag using only atomic operations, and skip a lock in
  the hot path, provided we clear the FULLYLOWERCASE flag before
  changing the case bitmap. :gl:`!10497`

- Use proper flexible arrays in rrl. ``e8f3ce70aa8``

  The single-element array hack can trip newer sanitizers or
  fortification levels.

  Found with UBSAN triggering the RRL system test with meson.
  :gl:`!10509`


