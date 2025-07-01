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

.. _build_bind:

Building BIND 9
---------------

To build on a Unix or Linux system, use:

::

    $ meson setup build-dir
    $ meson compile -C build-dir

Several environment variables affect compilation, and they can be set
before running ``meson setup``. The most significant ones are:

+--------------------+-------------------------------------------------+
| Variable           | Description                                     |
+====================+=================================================+
| ``CC``             | The C compiler to use. ``configure`` tries to   |
|                    | figure out the right one for supported systems. |
+--------------------+-------------------------------------------------+
| ``CC_LD``          | The C linker to use.                            |
+--------------------+-------------------------------------------------+
| ``CFLAGS``         | The C compiler flags. Defaults to an empty      |
|                    | string.                                         |
+--------------------+-------------------------------------------------+
| ``LDFLAGS``        | The linker flags. Defaults to an empty string.  |
+--------------------+-------------------------------------------------+

.. _build_dependencies:

Required Libraries
~~~~~~~~~~~~~~~~~~

To build BIND 9, the following packages must be installed:

- a C11-compliant compiler
- ``meson``
- ``libcrypto``, ``libssl``
- ``liburcu``
- ``libuv``
- ``perl``
- ``pkg-config`` / ``pkgconfig`` / ``pkgconf``

BIND 9 requires ``meson`` 0.61 or higher to configure and ``ninja``/``samurai``
to build from source.

BIND 9.20 requires ``libuv`` 1.37.0 or higher; using ``libuv`` >= 1.40.0 is
recommended. On older systems an updated ``libuv`` package needs to be
installed from sources, such as EPEL, PPA, or other native sources. The other
option is to build and install ``libuv`` from source.

OpenSSL 1.1.1 or newer is required. If the OpenSSL library is installed
in a nonstandard location adjust ``PKG_CONFIG_PATH`` or use the option
``--pkg-config-path``.

To use a PKCS#11 hardware service module for cryptographic operations,
PKCS#11 Provider (https://github.com/latchset/pkcs11-provider/tree/main)
must be compiled, configured and used directly in the OpenSSL 3.x.

The Userspace RCU library ``liburcu`` (https://liburcu.org/) is used
for lock-free data structures and concurrent safe memory reclamation.

On Linux, process capabilities are managed in user space using the
``libcap`` library
(https://git.kernel.org/pub/scm/libs/libcap/libcap.git/), which can be
installed on most Linux systems via the ``libcap-dev`` or
``libcap-devel`` package.

Optional Features
~~~~~~~~~~~~~~~~~

To see a full list of configuration options, run ``meson configure``.

To improve performance, use of the ``jemalloc`` library
(https://jemalloc.net/) is strongly recommended. Version 4.0.0 or newer is
required when in use.

To support :rfc:`DNS over HTTPS (DoH) <8484>`, the server must be linked
with ``libnghttp2`` (https://nghttp2.org/). If the library is
unavailable, ``-Ddoh=disabled`` can be used to disable DoH support.

To support the HTTP statistics channel, the server must be linked with
at least one of the following libraries: ``libxml2``
(https://gitlab.gnome.org/GNOME/libxml2/-/wikis/home) or ``json-c``
(https://github.com/json-c/json-c). If these are installed at a nonstandard
location, adjust ``PKG_CONFIG_PATH`` or use the option ``--pkg-config-path``.

To support compression on the HTTP statistics channel, the server must
be linked against ``zlib`` (https://zlib.net/). If this is installed in
a nonstandard location, adjust ``PKG_CONFIG_PATH`` or use the option
``--pkg-config-path``. Compression can be switched off with
``-Dzlib=disabled``.

To support storing configuration data for runtime-added zones in an LMDB
database, the server must be linked with ``liblmdb``
(https://github.com/LMDB/lmdb). If this is installed in a nonstandard
location, adjust ``PKG_CONFIG_PATH`` or use the option ``--pkg-config-path``.

To support MaxMind GeoIP2 location-based ACLs, the server must be linked
with ``libmaxminddb`` (https://maxmind.github.io/libmaxminddb/). This is
turned on by default if the library is found; if the library is installed in
a nonstandard location, adjust ``PKG_CONFIG_PATH`` or use the option
``--pkg-config-path``. GeoIP2 support can be switched off with
``-Dgeoip=disabled``.

For DNSTAP packet logging, ``libfstrm``
(https://github.com/farsightsec/fstrm) and ``libprotobuf-c``
(https://protobuf.dev) must be installed, and
BIND must be configured with ``-Ddnstap=enabled``.

To support internationalized domain names in :iscman:`dig`, ``libidn2``
(https://www.gnu.org/software/libidn/#libidn2) must be installed. If the
library is installed in a nonstandard location, adjust ``PKG_CONFIG_PATH`` or
use the option ``--pkg-config-path``. IDN support can be switched off with
``-Didn=disabled``.

For line editing in :iscman:`nsupdate` and :iscman:`nslookup`,
the ``libedit`` library (https://www.thrysoee.dk/editline/) must be
installed. If these are installed at a nonstandard location, adjust
``PKG_CONFIG_PATH`` or use the option ``--pkg-config-path``.

The ``-Dtrace-logging=query`` option causes :iscman:`named` to log every step
while processing every query. The ``-Dtrace-logging=query,single`` option turns
on the same verbose tracing, but allows an individual query to be
separately traced by setting its query ID to 0. These options should
only be enabled when debugging, because they have a significant negative
impact on query performance.

``meson install`` installs :iscman:`named` and the various BIND 9 libraries. By
default, installation is into /usr/local, but this can be changed with
the ``--prefix`` option when running ``meson setup``.

The option ``--sysconfdir`` can be specified to set the directory where
configuration files such as :iscman:`named.conf` go by default;
``--localstatedir`` can be used to set the default parent directory of
``run/named.pid``. ``--sysconfdir`` defaults to ``$prefix/etc`` and
``--localstatedir`` defaults to ``$prefix/var``.

macOS
~~~~~

Building on macOS assumes that the “Command Tools for Xcode” are
installed. These can be downloaded from
https://developer.apple.com/xcode/resources/ or, if Xcode is already
installed, simply run ``xcode-select --install``. (Note that an Apple ID
may be required to access the download page.)

Packager Builds
~~~~~~~~~~~~~~~

Packagers are recommended to use the ``plain`` optimization level or the
``plain`` build type when setting up the build directory. This will also
disable the default hardening flags and any such flag must be set with
``CFLAGS``. The top ``meson.build`` file in the source tree can be
inspected for recommended flags.
