.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.14
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- New configuration options, ``tcp-receive-buffer``, ``tcp-send-buffer``,
  ``udp-receive-buffer``, and ``udp-send-buffer``, have been added.  These
  options allows the operator to fine tune the receiving and sending
  buffers in the operating system.  On busy servers, increasing the value
  of the receive buffers can prevent the server from dropping the packets
  during short spikes, and decreasing the value would prevent the server to
  became clogged up with queries that are too old and have already timeouted
  on the receiving side. :gl:`#2313`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- Fix a race condition in reading and writing key files for KASP zones in
  multiple views. :gl:`#1875`

- Check ``key-directory`` conflicts in ``named.conf`` for zones in multiple
  views with different ``dnssec-policy``. Using the same ``key-directory`` for
  such zones is not allowed. :gl:`#2463`
