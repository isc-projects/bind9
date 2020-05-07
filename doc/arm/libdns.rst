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

.. _bind9.library:

BIND 9 DNS Library Support
==========================

This version of BIND 9 "exports" its internal libraries so that they can
be used by third-party applications more easily (we call them "export"
libraries in this document). Certain library functions are altered from
specific BIND-only behavior to more generic behavior when used by other
applications; to enable this generic behavior, the calling program
initializes the libraries by calling ``isc_lib_register()``.

In addition to DNS-related APIs that are used within BIND 9, the
libraries provide the following features:

-  The "DNS client" module. This is a higher level API that provides an
   interface to name resolution, single DNS transaction with a
   particular server, and dynamic update. Regarding name resolution, it
   supports advanced features such as DNSSEC validation and caching.
   This module supports both synchronous and asynchronous mode.

-  The "IRS" (Information Retrieval System) library. It provides an
   interface to parse the traditional ``resolv.conf`` file and more
   advanced, DNS-specific configuration file for the rest of this
   package (see the description for the ``dns.conf`` file below).

-  As part of the IRS library, the standard address-name mapping
   functions, ``getaddrinfo()`` and ``getnameinfo()``, are provided.
   They use the DNSSEC-aware validating resolver backend, and could use
   other advanced features of the BIND 9 libraries such as caching. The
   ``getaddrinfo()`` function resolves both A and AAAA RRs concurrently
   when the address family is unspecified.

-  An experimental framework to support other event libraries than BIND
   9's internal event task system.

Installation
------------

::

   $ make install


Normal installation of BIND will also install library object and header
files. Root privilege is normally required.

To see how to build your own application after the installation, see
``lib/samples/Makefile-postinstall.in``.

Known Defects/Restrictions
--------------------------

-  The "fixed" RRset order is not (currently) supported in the export
   library. If you want to use "fixed" RRset order for, e.g. ``named``
   while still building the export library even without the fixed order
   support, build them separately:

   ::

      $ ./configure --enable-fixed-rrset [other flags, but not --enable-exportlib]
      $ make
      $ ./configure --enable-exportlib [other flags, but not --enable-fixed-rrset]
      $ cd lib/export
      $ make

-  :rfc:`5011` is not supported in the validating stub resolver of the
   export library. In fact, it is not clear whether it should: trust
   anchors would be a system-wide configuration which would be managed
   by an administrator, while the stub resolver will be used by ordinary
   applications run by a normal user.

-  Not all common ``/etc/resolv.conf`` options are supported in the IRS
   library. The only available options in this version are ``debug`` and
   ``ndots``.

The dns.conf File
-----------------

The IRS library supports an "advanced" configuration file related to the
DNS library for configuration parameters that would be beyond the
capability of the ``resolv.conf`` file. Specifically, it is intended to
provide DNSSEC related configuration parameters. By default the path to
this configuration file is ``/etc/dns.conf``. This module is very
experimental and the configuration syntax or library interfaces may
change in future versions. Currently, only the ``trusted-keys``
statement is supported, whose syntax is the same as the same statement
in ``named.conf``. (See :ref:`trusted-keys` for details.)

Sample Applications
-------------------

Some sample application programs using this API are provided for
reference. The following is a brief description of these applications.

sample: a simple stub resolver utility
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sends a query of a given name (of a given optional RR type) to a
specified recursive server and prints the result as a list of RRs. It
can also act as a validating stub resolver if a trust anchor is given
via a set of command line options.

Usage: sample [options] server_address hostname

Options and Arguments:

``-t RRtype``
   specify the RR type of the query. The default is the A RR.

``[-a algorithm] [-e] -k keyname -K keystring``
   specify a command-line DNS key to validate the answer. For example,
   to specify the following DNSKEY of example.com: example.com. 3600 IN
   DNSKEY 257 3 5 xxx specify the options as follows:

   ::

      -e -k example.com -K "xxx"


   -e means that this key is a zone's "key signing key" (also known as
   "secure entry point"). When -a is omitted rsasha1 will be used by
   default.

``-s domain:alt_server_address``
   specify a separate recursive server address for the specific
   "domain". Example: -s example.com:2001:db8::1234

``server_address``
   an IP(v4/v6) address of the recursive server to which queries are
   sent.

``hostname``
   the domain name for the query

sample-async: a simple stub resolver, working asynchronously
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Similar to "sample", but accepts a list of (query) domain names as a
separate file and resolves the names asynchronously.

Usage: sample-async [-s server_address] [-t RR_type] input_file

Options and Arguments:

``-s server_address``
   an IPv4 address of the recursive server to which queries are sent.
   (IPv6 addresses are not supported in this implementation)
``-t RR_type``
   specify the RR type of the queries. The default is the A RR.
``input_file``
   a list of domain names to be resolved. each line consists of a single
   domain name. Example:
   ::

            www.example.com
            mx.example.net
            ns.xxx.example


sample-request: a simple DNS transaction client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sends a query to a specified server, and prints the response with
minimal processing. It doesn't act as a "stub resolver": it stops the
processing once it gets any response from the server, whether it's a
referral or an alias (CNAME or DNAME) that would require further queries
to get the ultimate answer. In other words, this utility acts as a very
simplified ``dig``.

Usage: sample-request [-t RRtype] server_address hostname

Options and Arguments:

``-t RRtype``
   specify the RR type of the queries. The default is the A RR.

``server_address``
   an IP(v4/v6) address of the recursive server to which the query is
   sent.

``hostname``
   the domain name for the query

sample-gai: getaddrinfo() and getnameinfo() test code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a test program to check ``getaddrinfo()`` and ``getnameinfo()``
behavior. It takes a host name as an argument, calls ``getaddrinfo()``
with the given host name, and calls ``getnameinfo()`` with the resulting
IP addresses returned by ``getaddrinfo()``. If the dns.conf file exists
and defines a trust anchor, the underlying resolver will act as a
validating resolver, and ``getaddrinfo()``/``getnameinfo()`` will fail
with an EAI_INSECUREDATA error when DNSSEC validation fails.

Usage: sample-gai hostname

sample-update: a simple dynamic update client program
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Accepts a single update command as a command-line argument, sends an
update request message to the authoritative server, and shows the
response from the server. In other words, this is a simplified
``nsupdate``.

Usage: sample-update [options] (add|delete) "update data"

Options and Arguments:

``-a auth_server``
   An IP address of the authoritative server that has authority for the
   zone containing the update name. This should normally be the primary
   authoritative server that accepts dynamic updates. It can also be a
   secondary server that is configured to forward update requests to the
   primary server.

``-k keyfile``
   A TSIG key file to secure the update transaction. The keyfile format
   is the same as that for the nsupdate utility.

``-p prerequisite``
   A prerequisite for the update (only one prerequisite can be
   specified). The prerequisite format is the same as that is accepted
   by the nsupdate utility.

``-r recursive_server``
   An IP address of a recursive server that this utility will use. A
   recursive server may be necessary to identify the authoritative
   server address to which the update request is sent.

``-z zonename``
   The domain name of the zone that contains

``(add|delete)``
   Specify the type of update operation. Either "add" or "delete" must
   be specified.

``update data``
   Specify the data to be updated. A typical example of the data would
   look like "name TTL RRtype RDATA".

.. note::

   In practice, either -a or -r must be specified. Others can be
   optional; the underlying library routine tries to identify the
   appropriate server and the zone name for the update.

Examples: assuming the primary authoritative server of the
dynamic.example.com zone has an IPv6 address 2001:db8::1234,

::

   $ sample-update -a sample-update -k Kxxx.+nnn+mmmm.key add "foo.dynamic.example.com 30 IN A 192.168.2.1"

adds an A RR for foo.dynamic.example.com using the given key.

::

   $ sample-update -a sample-update -k Kxxx.+nnn+mmmm.key delete "foo.dynamic.example.com 30 IN A"

removes all A RRs for foo.dynamic.example.com using the given key.

::

   $ sample-update -a sample-update -k Kxxx.+nnn+mmmm.key delete "foo.dynamic.example.com"

removes all RRs for foo.dynamic.example.com using the given key.

nsprobe: domain/name server checker in terms of RFC 4074
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Checks a set of domains to see the name servers of the domains behave
correctly in terms of :rfc:`4074`. This is included in the set of sample
programs to show how the export library can be used in a DNS-related
application.

Usage: nsprobe [-d] [-v [-v...]] [-c cache_address] [input_file]

Options

``-d``
   Run in "debug" mode. With this option nsprobe will dump every RRs it
   receives.

``-v``
   Increase verbosity of other normal log messages. This can be
   specified multiple times.

``-c cache_address``
   Specify an IP address of a recursive (caching) name server. nsprobe
   uses this server to get the NS RRset of each domain and the A and/or
   AAAA RRsets for the name servers. The default value is 127.0.0.1.

``input_file``
   A file name containing a list of domain (zone) names to be probed.
   when omitted the standard input will be used. Each line of the input
   file specifies a single domain name such as "example.com". In general
   this domain name must be the apex name of some DNS zone (unlike
   normal "host names" such as "www.example.com"). nsprobe first
   identifies the NS RRsets for the given domain name, and sends A and
   AAAA queries to these servers for some "widely used" names under the
   zone; specifically, adding "www" and "ftp" to the zone name.

Library References
------------------

As of this writing, there is no formal "manual" for the libraries,
except this document, header files (some of which provide pretty
detailed explanations), and sample application programs.
