.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

..
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.

   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

.. _relnotes:

Release Notes
=============

.. _relnotes_intro:

Introduction
------------

BIND 9.15 is an unstable development release of BIND. This document
summarizes new features and functional changes that have been introduced
on this branch. With each development release leading up to the stable
BIND 9.16 release, this document will be updated with additional
features added and bugs fixed.

.. _relnotes_versions:

Note on Version Numbering
-------------------------

Until BIND 9.12, new feature development releases were tagged as "alpha"
and "beta", leading up to the first stable release for a given
development branch, which always ended in ".0". More recently, BIND
adopted the "odd-unstable/even-stable" release numbering convention.
There will be no "alpha" or "beta" releases in the 9.15 branch, only
increasing version numbers. So, for example, what would previously have
been called 9.15.0a1, 9.15.0a2, 9.15.0b1, and so on, will instead be
called 9.15.0, 9.15.1, 9.15.2, etc.

The first stable release from this development branch will be renamed as
9.16.0. Thereafter, maintenance releases will continue on the 9.16
branch, while unstable feature development proceeds in 9.17.

.. _relnotes_platforms:

Supported Platforms
-------------------

To build on UNIX-like systems, BIND requires support for POSIX.1c
threads (IEEE Std 1003.1c-1995), the Advanced Sockets API for IPv6
(:rfc:`3542`), and standard atomic operations provided by the C compiler.

The OpenSSL cryptography library must be available for the target
platform. A PKCS#11 provider can be used instead for Public Key
cryptography (i.e., DNSSEC signing and validation), but OpenSSL is still
required for general cryptography operations such as hashing and random
number generation.

More information can be found in the ``PLATFORMS.md`` file that is
included in the source distribution of BIND 9. If your compiler and
system libraries provide the above features, BIND 9 should compile and
run. If that isn't the case, the BIND development team will generally
accept patches that add support for systems that are still supported by
their respective vendors.

.. _relnotes_download:

Download
--------

The latest versions of BIND 9 software can always be found at
http://www.isc.org/downloads/. There you will find additional
information about each release, source code, and pre-compiled versions
for Microsoft Windows operating systems.

.. _relnotes_security:

Security Fixes
--------------

-  None.

.. _relnotes_features:

New Features
------------

-  The new ``add-soa`` option specifies whether or not the
   ``response-policy`` zone's SOA record should be included in the
   additional section of RPZ responses. [GL #865]

.. _relnotes_removed:

Removed Features
----------------

-  The ``dnssec-enable`` option has been deprecated and no longer has
   any effect. DNSSEC responses are always enabled if signatures and
   other DNSSEC data are present. [GL #866]

.. _relnotes_changes:

Feature Changes
---------------

-  None.

.. _relnotes_bugs:

Bug Fixes
---------

-  The ``allow-update`` and ``allow-update-forwarding`` options were
   inadvertently treated as configuration errors when used at the
   ``options`` or ``view`` level. This has now been corrected. [GL #913]

.. _relnotes_license:

License
-------

BIND is open source software licenced under the terms of the Mozilla
Public License, version 2.0 (see the ``LICENSE`` file for the full
text).

The license requires that if you make changes to BIND and distribute
them outside your organization, those changes must be published under
the same license. It does not require that you publish or disclose
anything other than the changes you have made to our software. This
requirement does not affect anyone who is using BIND, with or without
modifications, without redistributing it, nor anyone redistributing BIND
without changes.

Those wishing to discuss license compliance may contact ISC at
https://www.isc.org/mission/contact/.

.. _end_of_life:

End of Life
-----------

BIND 9.15 is an unstable development branch. When its development is
complete, it will be renamed to BIND 9.16, which will be a stable
branch.

The end of life date for BIND 9.16 has not yet been determined. For
those needing long term support, the current Extended Support Version
(ESV) is BIND 9.11, which will be supported until at least December
2021. See https://www.isc.org/downloads/software-support-policy/ for
details of ISC's software support policy.

.. _relnotes_thanks:

Thank You
---------

Thank you to everyone who assisted us in making this release possible.
If you would like to contribute to ISC to assist us in continuing to
make quality open source software, please visit our donations page at
http://www.isc.org/donate/.
