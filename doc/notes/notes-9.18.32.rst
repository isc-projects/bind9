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

Notes for BIND 9.18.32
----------------------

New Features
~~~~~~~~~~~~

- Update bind.keys with the new 2025 IANA root key.

  Add an 'initial-ds' entry to bind.keys for the new root key, ID 38696,
  which is scheduled for publication in January 2025. :gl:`#4896`

Removed Features
~~~~~~~~~~~~~~~~

- Move contributed DLZ modules into a separate repository.

  The DLZ modules are poorly maintained as we only ensure they can still
  be compiled, the DLZ interface is blocking, so anything that blocks
  the query to the database blocks the whole server and they should not
  be used except in testing.  The DLZ interface itself is going to be
  scheduled for removal.

  The DLZ modules now live in
  https://gitlab.isc.org/isc-projects/dlz-modules repository.
  :gl:`#4865`

Feature Changes
~~~~~~~~~~~~~~~

- Emit more helpful log for exceeding max-records-per-type.

  The new log message is emitted when adding or updating an RRset fails
  due to exceeding the max-records-per-type limit. The log includes the
  owner name and type, corresponding zone name, and the limit value. It
  will be emitted on loading a zone file, inbound zone transfer (both
  AXFR and IXFR), handling a DDNS update, or updating a cache DB. It's
  especially helpful in the case of zone transfer, since the secondary
  side doesn't have direct access to the offending zone data.

  It could also be used for max-types-per-name, but this change doesn't
  implement it yet as it's much less likely to happen in practice.

- Harden key management when key files have become unavailabe.

  Prior to doing key management, BIND 9 will check if the key files on
  disk match the expected keys. If key files for previously observed
  keys have become unavailable, this will prevent the internal key
  manager from running.

- Revert "Fix NSEC3 closest encloser lookup for names with empty
  non-terminals"

  The fix for #4950 should have never been backported to 9.18. Revert
  the change.

  This reverts MR !9632

  History: A performance improvement for NSEC3 closest encloser lookups
  (#4460) was introduced (in MR !9436) and backported to 9.20 (MR !9438)
  and to 9.18 in (MR !9439). It was released in 9.18.30 (and 9.20.2 and
  9.21.1).

  There was a bug in the code (#4950), so we reverted the change in
  !9611, !9613 and !9614 (not released).

  Then a new attempt was merged in main (MR !9610) and backported to
  9.20 (MR !9631) and 9.18 (MR !9632). The latter should not have been
  backported.

  Furthermore, the initial MR used the wrong MR title so the change was
  never added to the release note. This is done in main with MR !9598
  and backports to 9.20 (MR !9615) and 9.18 (MR !9616).

  The new release notes for 9.21 and 9.20 should probably say that the
  bug is fixed. The new release notes for 9.18 should probably say that
  the change is reverted.

Bug Fixes
~~~~~~~~~

- '{&dns}' is as valid as '{?dns}' in a SVCB's dohpath.

  `dig` fails to parse a valid (as far as I can tell, and accepted by
  `kdig` and `Wireshark`) `SVCB` record with a `dohpath` URI template
  containing a `{&dns}`, like `dohpath=/some/path?key=value{&dns}"`. If
  the URI template contains a `{?dns}` instead `dig` is happy, but my
  understanding of rfc9461 and section 1.2. "Levels and Expression
  Types" of rfc6570 is that `{&dns}` is valid. See for example section
  1.2. "Levels and Expression Types" of rfc6570.

  Note that Peter van Dijk suggested that `{dns}` and
  `{dns,someothervar}` might be valid forms as well, so my patch might
  be too restrictive, although it's anyone's guess how DoH clients would
  handle complex templates. :gl:`#4922`

- Fix NSEC3 closest encloser lookup for names with empty non-terminals.

  The performance improvement for finding the NSEC3 closest encloser
  when generating authoritative responses could cause servers to return
  incorrect NSEC3 records in some cases. This has been fixed.
  :gl:`#4950`

- Restore values when dig prints command line.

  Options of the form `[+-]option=<value>` failed to display the value
  on the printed command line. This has been fixed. :gl:`#4993`

- Provide more visibility into configuration errors.

  by logging SSL_CTX_use_certificate_chain_file and
  SSL_CTX_use_PrivateKey_file errors individually. :gl:`#5008`


