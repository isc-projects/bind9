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

Building BIND
-------------

Minimally, BIND requires a UNIX or Linux system with an ANSI C compiler,
basic POSIX support, and a 64-bit integer type. BIND also requires the
``libuv`` asynchronous I/O library, and a cryptography provider library
such as OpenSSL or a hardware service module supporting PKCS#11. On
Linux, BIND requires the ``libcap`` library to set process privileges,
though this requirement can be overridden by disabling capability
support at compile time. See `Compile-time options <#opts>`__ below for
details on other libraries that may be required to support optional
features.

Successful builds have been observed on many versions of Linux and UNIX,
including RHEL/CentOS/Oracle Linux, Fedora, Debian, Ubuntu, SLES,
openSUSE, Slackware, Alpine, FreeBSD, NetBSD, OpenBSD, macOS, Solaris,
OpenIndiana, OmniOS CE, HP-UX, and OpenWRT.

BIND is also available for Windows Server 2012 R2 and higher. See
``win32utils/build.txt`` for details on building for Windows systems.

To build on a UNIX or Linux system, use:

::

       $ ./configure
       $ make

If you’re planning on making changes to the BIND 9 source, you should
run ``make depend``. If you’re using Emacs, you might find ``make tags``
helpful.

Several environment variables that can be set before running
``configure`` will affect compilation. Significant ones are:

+--------------------+-------------------------------------------------+
| Variable           | Description                                     |
+====================+=================================================+
| ``CC``             | The C compiler to use. ``configure`` tries to   |
|                    | figure out the right one for supported systems. |
+--------------------+-------------------------------------------------+
| ``CFLAGS``         | C compiler flags. Defaults to include -g and/or |
|                    | -O2 as supported by the compiler. Please        |
|                    | include ‘-g’ if you need to set ``CFLAGS``.     |
+--------------------+-------------------------------------------------+
| ``STD_CINCLUDES``  | System header file directories. Can be used to  |
|                    | specify where add-on thread or IPv6 support is, |
|                    | for example. Defaults to empty string.          |
+--------------------+-------------------------------------------------+
| ``STD_CDEFINES``   | Any additional preprocessor symbols you want    |
|                    | defined. Defaults to empty string. For a list   |
|                    | of possible settings, see the file              |
|                    | `OPTIONS <OPTIONS.md>`__.                       |
+--------------------+-------------------------------------------------+
| ``LDFLAGS``        | Linker flags. Defaults to empty string.         |
+--------------------+-------------------------------------------------+
| ``BUILD_CC``       | Needed when cross-compiling: the native C       |
|                    | compiler to use when building for the target    |
|                    | system.                                         |
+--------------------+-------------------------------------------------+
| ``BUILD_CFLAGS``   | ``CFLAGS`` for the target system during         |
|                    | cross-compiling.                                |
+--------------------+-------------------------------------------------+
| ``BUILD_CPPFLAGS`` | ``CPPFLAGS`` for the target system during       |
|                    | cross-compiling.                                |
+--------------------+-------------------------------------------------+
| ``BUILD_LDFLAGS``  | ``LDFLAGS`` for the target system during        |
|                    | cross-compiling.                                |
+--------------------+-------------------------------------------------+
| ``BUILD_LIBS``     | ``LIBS`` for the target system during           |
|                    | cross-compiling.                                |
+--------------------+-------------------------------------------------+

Additional environment variables affecting the build are listed at the
end of the ``configure`` help text, which can be obtained by running the
command:

::

   $ ./configure --help

macOS
~~~~~

Building on macOS assumes that the “Command Tools for Xcode” is
installed. This can be downloaded from
https://developer.apple.com/download/more/ or, if you have Xcode already
installed, you can run ``xcode-select --install``. (Note that an Apple
ID may be required to access the download page.)

Dependencies
------------

Portions of BIND that are written in Python, including
``dnssec-keymgr``, ``dnssec-coverage``, ``dnssec-checkds``, and some of
the system tests, require the ``argparse``, ``ply`` and
``distutils.core`` modules to be available. ``argparse`` is a standard
module as of Python 2.7 and Python 3.2. ``ply`` is available from
https://pypi.python.org/pypi/ply. ``distutils.core`` is required for
installation.

Compile-time options
~~~~~~~~~~~~~~~~~~~~

To see a full list of configuration options, run ``configure --help``.

To build shared libraries, specify ``--with-libtool`` on the
``configure`` command line.

For the server to support DNSSEC, you need to build it with crypto
support. To use OpenSSL, you should have OpenSSL 1.0.2e or newer
installed. If the OpenSSL library is installed in a nonstandard
location, specify the prefix using ``--with-openssl=<PREFIX>`` on the
configure command line. To use a PKCS#11 hardware service module for
cryptographic operations, specify the path to the PKCS#11 provider
library using ``--with-pkcs11=<PREFIX>``, and configure BIND with
``--enable-native-pkcs11``.

To support the HTTP statistics channel, the server must be linked with
at least one of the following libraries: ``libxml2`` http://xmlsoft.org
or ``json-c`` https://github.com/json-c/json-c. If these are installed
at a nonstandard location, then:

-  for ``libxml2``, specify the prefix using ``--with-libxml2=/prefix``,
-  for ``json-c``, adjust ``PKG_CONFIG_PATH``.

To support compression on the HTTP statistics channel, the server must
be linked against ``libzlib``. If this is installed in a nonstandard
location, specify the prefix using ``--with-zlib=/prefix``.

To support storing configuration data for runtime-added zones in an LMDB
database, the server must be linked with liblmdb. If this is installed
in a nonstandard location, specify the prefix using
``with-lmdb=/prefix``.

To support MaxMind GeoIP2 location-based ACLs, the server must be linked
with ``libmaxminddb``. This is turned on by default if the library is
found; if the library is installed in a nonstandard location, specify
the prefix using ``--with-maxminddb=/prefix``. GeoIP2 support can be
switched off with ``--disable-geoip``.

For DNSTAP packet logging, you must have installed ``libfstrm``
https://github.com/farsightsec/fstrm and ``libprotobuf-c``
https://developers.google.com/protocol-buffers, and BIND must be
configured with ``--enable-dnstap``.

Certain compiled-in constants and default settings can be decreased to
values better suited to small machines, e.g. OpenWRT boxes, by
specifying ``--with-tuning=small`` on the ``configure`` command line.
This will decrease memory usage by using smaller structures, but will
degrade performance.

On Linux, process capabilities are managed in user space using the
``libcap`` library, which can be installed on most Linux systems via the
``libcap-dev`` or ``libcap-devel`` package. Process capability support
can also be disabled by configuring with ``--disable-linux-caps``.

On some platforms it is necessary to explicitly request large file
support to handle files bigger than 2GB. This can be done by using
``--enable-largefile`` on the ``configure`` command line.

Support for the “fixed” rrset-order option can be enabled or disabled by
specifying ``--enable-fixed-rrset`` or ``--disable-fixed-rrset`` on the
configure command line. By default, fixed rrset-order is disabled to
reduce memory footprint.

The ``--enable-querytrace`` option causes ``named`` to log every step of
processing every query. This should only be enabled when debugging,
because it has a significant negative impact on query performance.

``make install`` will install ``named`` and the various BIND 9
libraries. By default, installation is into /usr/local, but this can be
changed with the ``--prefix`` option when running ``configure``.

You may specify the option ``--sysconfdir`` to set the directory where
configuration files like ``named.conf`` go by default, and
``--localstatedir`` to set the default parent directory of
``run/named.pid``. ``--sysconfdir`` defaults to ``$prefix/etc`` and
``--localstatedir`` defaults to ``$prefix/var``.
