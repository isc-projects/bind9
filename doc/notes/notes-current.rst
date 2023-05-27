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

Notes for BIND 9.19.14
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Add support for multi-signer model 2 (RFC 8901) when using
  ``inline-signing``. :gl:`#2710`

- A new option to :any:`dnssec-policy` has been added, :any:`cdnskey`, that
  allows you to enable or disable the publication of CDNSKEY records.
  :gl:`#4050`

- The read timeout in ``rndc`` can now be specified on the command line
  using the ``-t`` option, allowing commands that take a long time to
  complete sufficient time to do so. :gl:`#4046`

- The system test suite can now be executed with pytest (along with
  pytest-xdist for parallel execution). :gl:`#3978`

Removed Features
~~~~~~~~~~~~~~~~

- Special-case code that was originally added to allow GSS-TSIG to work
  around bugs in the Windows 2000 version of Active Directory has now
  been removed since Windows 2000 is long past end-of-life.
  The ``nsupdate -o`` option and the ``oldgsstsig`` command to ``nsupdate``
  have been deprecated, and are now treated as synonyms for ``nsupdate -g``
  and ``gsstsig`` respectively. :gl:`#4012`

Feature Changes
~~~~~~~~~~~~~~~

- Improve the responsiveness of the ``named`` serving as an authoritative DNS
  server for a delegation-heavy zone(s) shortly after loading such zone(s).
  :gl:`#4045`

Bug Fixes
~~~~~~~~~

- When the :any:`stale-answer-enable` option was enabled and the
  :any:`stale-answer-client-timeout` option was enabled and larger than 0,
  ``named`` was taking two places from the :any:`clients-per-query` limit for
  each client and was failing to gradually auto-tune its value, as configured.
  This has been fixed. :gl:`#4074`

- It could happen that after the :any:`stale-answer-client-timeout` duration,
  a delegation from cache was returned to the client. This has now been fixed.
  :gl:`#3950`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
