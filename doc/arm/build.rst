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

Building BIND 9
---------------

At a minimum, BIND requires a Unix or Linux system with an ANSI C
compiler, basic POSIX support, and a 64-bit integer type. BIND also
requires the ``libuv`` asynchronous I/O library, the ``nghttp2`` HTTP/2
library, the ``jemalloc`` memory allocation library, and the OpenSSL
cryptography library. On Linux, BIND requires the ``libcap`` library to
set process privileges, though this requirement can be overridden by
disabling capability support at compile time. See `Compile-time
options <#opts>`__ below for details on other libraries that may be
required to support optional features.

Successful builds have been observed on many versions of Linux and Unix,
including RHEL/CentOS/Oracle Linux, Fedora, Debian, Ubuntu, SLES,
openSUSE, Slackware, Alpine, FreeBSD, NetBSD, OpenBSD, macOS, Solaris,
OpenIndiana, OmniOS CE, HP-UX, and OpenWRT.

To build on a Unix or Linux system, use:

::

       $ autoreconf -fi (if you are building in the git repository)
       $ ./configure
       $ make

If you’re using Emacs, you might find ``make tags`` helpful.

Several environment variables, which can be set before running
``configure``, affect compilation. Significant ones are:

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
| ``LDFLAGS``        | Linker flags. Defaults to empty string.         |
+--------------------+-------------------------------------------------+

Additional environment variables affecting the build are listed at the
end of the ``configure`` help text, which can be obtained by running the
command:

::

   $ ./configure --help

macOS
~~~~~

Building on macOS assumes that the “Command Tools for Xcode” are
installed. These can be downloaded from
https://developer.apple.com/download/more/ or, if you have Xcode already
installed, you can run ``xcode-select --install``. (Note that an Apple
ID may be required to access the download page.)

Dependencies
~~~~~~~~~~~~

To build BIND you need to have the following packages installed:

::

   libuv
   pkg-config / pkgconfig / pkgconf

To build BIND from the git repository, you need the following tools
installed:

::

   autoconf (includes autoreconf)
   automake
   libtool

Compile-time options
~~~~~~~~~~~~~~~~~~~~

To see a full list of configuration options, run ``configure --help``.

For the server to support DNSSEC, you need to build it with crypto
support. To use OpenSSL, you must have OpenSSL 1.0.2e or newer
installed. If the OpenSSL library is installed in a nonstandard
location, specify the prefix using ``--with-openssl=<PREFIX>`` on the
configure command line. To use a PKCS#11 hardware service module for
cryptographic operations, it will be necessary to compile and use
engine_pkcs11 from the OpenSC project.

To support DNS over HTTPS, the server must be linked with
``libnghttp2``.

To support the HTTP statistics channel, the server must be linked with
at least one of the following libraries: ``libxml2`` http://xmlsoft.org
or ``json-c`` https://github.com/json-c/json-c. If these are installed
at a nonstandard location, then:

-  for ``libxml2``, specify the prefix using ``--with-libxml2=/prefix``.
-  for ``json-c``, adjust ``PKG_CONFIG_PATH``.

To support compression on the HTTP statistics channel, the server must
be linked against ``libzlib``. If this is installed in a nonstandard
location, specify the prefix using ``--with-zlib=/prefix``.

To support storing configuration data for runtime-added zones in an LMDB
database, the server must be linked with ``liblmdb``. If this is
installed in a nonstandard location, specify the prefix using
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
This decreases memory usage by using smaller structures, but degrades
performance.

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
processing every query. The ``--enable-singletrace`` option turns on the
same verbose tracing, but allows an individual query to be separately
traced by setting its query ID to 0. These options should only be
enabled when debugging, because they have a significant negative impact
on query performance.

``make install`` installs ``named`` and the various BIND 9 libraries. By
default, installation is into /usr/local, but this can be changed with
the ``--prefix`` option when running ``configure``.

You may specify the option ``--sysconfdir`` to set the directory where
configuration files like ``named.conf`` go by default, and
``--localstatedir`` to set the default parent directory of
``run/named.pid``. ``--sysconfdir`` defaults to ``$prefix/etc`` and
``--localstatedir`` defaults to ``$prefix/var``.
