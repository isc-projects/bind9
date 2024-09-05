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

Notes for BIND 9.18.30
----------------------

New Features
~~~~~~~~~~~~

- Print the full path of the working directory in startup log messages.

  named now prints its initial working directory during startup and the
  changed working directory when loading or reloading its configuration
  file if it has a valid 'directory' option defined. :gl:`#4731`

Feature Changes
~~~~~~~~~~~~~~~

- Follow the number of CPU set by taskset/cpuset.

  Administrators may wish to constrain the set of cores that BIND 9 runs
  on via the 'taskset', 'cpuset' or 'numactl' programs (or equivalent on
  other O/S).

  If the admin has used taskset, the `named` will now follow to
  automatically use the given number of CPUs rather than the system wide
  count. :gl:`#4884`

Bug Fixes
~~~~~~~~~

- Checking whether a EDDSA key was private or not was broken.

  Checking whether a EDDSA key was private or not was broken could lead
  to attempting to sign records with a public key and this could cause a
  segmentation failure (read of a NULL pointer) within OpenSSL.
  :gl:`#4855`

- Fix algoritm rollover bug when there are two keys with the same
  keytag.

  If there is an algorithm rollover and two keys of different algorithm
  share the same keytags, then there is a possibility that if we check
  that a key matches a specific state, we are checking against the wrong
  key. This has been fixed by not only checking for matching key tag but
  also key algorithm. :gl:`#4878`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
