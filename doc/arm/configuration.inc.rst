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

.. _configuration:

Configurations and Zone Files
=============================

In this chapter we provide some suggested configurations, along with
guidelines for their use. We suggest reasonable values for certain
option settings.

.. _sample_configuration:

Sample Configurations
---------------------

.. _cache_only_sample:

A Caching-only Name Server
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following sample configuration is appropriate for a caching-only
name server for use by clients internal to a corporation. All queries
from outside clients are refused using the ``allow-query`` option.
The same effect can be achieved using suitable firewall
rules.

::

   // Two corporate subnets we wish to allow queries from.
   acl corpnets { 192.168.4.0/24; 192.168.7.0/24; };
   options {
        allow-query { corpnets; };
   };
   // Provide a reverse mapping for the loopback
   // address 127.0.0.1
   zone "0.0.127.in-addr.arpa" {
        type primary;
        file "localhost.rev";
        notify no;
   };

.. _auth_only_sample:

An Authoritative-only Name Server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This sample configuration is for an authoritative-only server that is
the primary server for ``example.com`` and a secondary server for the subdomain
``eng.example.com``.

::

   options {
        // Do not allow access to cache
        allow-query-cache { none; };
        // This is the default
        allow-query { any; };
        // Do not provide recursive service
        recursion no;
   };

   // Provide a reverse mapping for the loopback
   // address 127.0.0.1
   zone "0.0.127.in-addr.arpa" {
        type primary;
        file "localhost.rev";
        notify no;
   };
   // We are the primary server for example.com
   zone "example.com" {
        type primary;
        file "example.com.db";
        // IP addresses of secondary servers allowed to
        // transfer example.com
        allow-transfer {
         192.168.4.14;
         192.168.5.53;
        };
   };
   // We are a secondary server for eng.example.com
   zone "eng.example.com" {
        type secondary;
        file "eng.example.com.bk";
        // IP address of eng.example.com primary server
        primaries { 192.168.4.12; };
   };

.. _load_balancing:

Load Balancing
--------------

A primitive form of load balancing can be achieved in the DNS by using
multiple records (such as multiple A records) for one name.

For example, assuming three HTTP servers with network addresses of
10.0.0.1, 10.0.0.2, and 10.0.0.3, a set of records such as the following
means that clients will connect to each machine one-third of the time:

+-----------+------+----------+----------+----------------------------+
| Name      | TTL  | CLASS    | TYPE     | Resource Record (RR) Data  |
+-----------+------+----------+----------+----------------------------+
| www       | 600  |   IN     |   A      |   10.0.0.1                 |
+-----------+------+----------+----------+----------------------------+
|           | 600  |   IN     |   A      |   10.0.0.2                 |
+-----------+------+----------+----------+----------------------------+
|           | 600  |   IN     |   A      |   10.0.0.3                 |
+-----------+------+----------+----------+----------------------------+

When a resolver queries for these records, BIND rotates them and
responds to the query with the records in a different order. In the
example above, clients randomly receive records in the order 1, 2,
3; 2, 3, 1; and 3, 1, 2. Most clients use the first record returned
and discard the rest.

For more detail on ordering responses, check the ``rrset-order``
sub-statement in the ``options`` statement; see :ref:`rrset_ordering`.

