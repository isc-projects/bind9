<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

# Netmgr

Netmgr (aka rainbow duck) is the new networking system for BIND. It's based
on libuv, although it does not expose any of the libuv API, in order to
keep the API agnostic of underlying library.

## A bit of history

Networking in BIND9 up to 9.12 works with a single event loop (epoll() on
Linux, kqueue on FreeBSD, etc).

When a client wants to read from a socket, it creates a socket event
associated with a task that will receive this event. An
`isc_socket_{read,write,etc.}` operation tries to read directly from
the socket; if it succeeds, it sends the socket event to the task
provided by the callee. If it doesn't, it adds an event to an event
loop, and when this event is received the listener is re-set, and an
internal task is launched to read the data from the socket.  After the
internal task is done, it launches the task from socket event provided
by the callee. This means that a simple socket operation causes a
lot of context switches.

9.14 fixed some of these issues by having multiple event loops in separate
threads (one per CPU), that can read the data immediately and then call
the socket event, but this is still sub-optimal.

## Basic concepts

### `isc_nm_t`

The `isc_nm_t` structure represents the network manager itself.  It
contains a configurable number (generally the same as the number of CPUs)
of 'networker' objects, each of which represents a thread for executing
networking events. 

The manager contains flags to indicate whether it has been paused or
interlocked, and counters for the number of workers running and the
number of workers paused.

Each networker object contains a queue of incoming asynchronous events
and a pool of buffers into which messages will be copied when received.

### `isc_nmsocket_t`

`isc_nmsocket_t` is a wrapper around a libuv socket. It is configured
with 

### `isc_nmhandle_t`

An `isc_nmhandle_t` object represents an interface that can be read or
written.  For TCP it's a socket, and for UDP it's a socket with a peer
address.  It is always associated with one and only one `isc_nmsocket_t`
object.

When a handle object is allocated, it may be allocated with a block of
'extra' space in which another object will be stored that is associated
with that handle: for example, an `ns_client_t` structure storing
information about an incoming request.

The handle is reference counted; when references drop to zero it calls
the 'reset' callback for its associated object and places itself onto
a stack of inactive handles in its corresponding `isc_nmsocket_t`
structure so it can be quickly reused when the next incoming message
is received.  When the handle is freed (which may happen if the socket's
inactive-handles stack is full or when the socket is destroyed) then the
associated object's 'put' callback will be called to free any resources
it allocated.

## Streaming Protocols

Currently, we have two streaming protocols available in Network Manager - TCP
and TLS.  The underlying premise is that they both expose the same interface to
the clients.

### Servers (Listening)

The users of the API calls ``isc_nm_listentcp()`` or ``isc_nm_listentls()`` with
the accept callback as argument.

When connection is accepted, the accept callback is called with a handle and
status and it can return a non-``ISC_R_RESULT`` to abort the connection.

The accept callback should generally immediately call ``isc_nm_read()`` to setup
the read callback.  Not doing so, can lead to a data race - if the NM is shut
down before the ``isc_nm_read()`` call, the socket can become dangling until
``isc_nm_read()`` is finally called.

When ``isc_nm_read()`` is called, the read callback will receive:

- 0-<n> calls with ``ISC_R_SUCCESS`` state
- exactly 1 call with non-``ISC_R_SUCCESS`` state when the connection is
  interrupted (locally closed, remotely closed, NM shutting down, etc.)

The ``isc_nm_read_stop()`` can be used to pause reading from the socket and only
the final non-``ISC_R_SUCCESS`` callback will be received in such case.

### Clients (Connecting)

The users of the API calls ``isc_nm_tcpconnect()`` or ``isc_nm_tlsconnect()``
with the connect callback as argument.

When connection is established, the connect callback is called with a handle and
status.

The connect callback should generally immediately call ``isc_nm_read()`` - see
the same caveat in the accepting part.

When ``isc__nm_read()`` is called on the connected socket, the read callback
will receive:

- 0-<n> calls with ``ISC_R_SUCCESS`` state
- exactly 1 call with non-``ISC_R_SUCCESS`` state when the connection is
  interrupted (locally closed, remotely closed, NM shutting down, etc.)

The ``isc_nm_read_stop()`` can be used to pause reading from the socket and only
the final non-``ISC_R_SUCCESS`` callback will be received in such case.

## DNS Message Protocols

Currently, we have three (four) DNS Message Protocols implemented in the Network Manager:

- UDP
- StreamDNS (TCPDNS and TLSDNS)
- HTTP

### Servers (Listening)

The users of the API calls ``isc_nm_listenudp()`` or
``isc_nm_listenstreamdns()`` with:

- accept callback
- read callback

The StreamDNS accepts an optional TLS context for DoT (otherwise DNS over TCP
will be used).

The HTTP listening is more complicated - the users need to setup the endpoints
with the read callback and pass the 1-<n> endpoints to the
``isc_nm_listenhttp()`` call.

The accept callback is used only to implement "firewall"-like functionality, it
could be used to tear down the connection early in the process.

After the connection has been accepted, the read callback will receive:

- 0-<n> calls with ``ISC_R_SUCCESS`` state
- exactly 1 call with non-``ISC_R_SUCCESS`` state when the connection is
  interrupted (locally closed, remotely closed, NM shutting down, etc.)

Each read callback will contain a full assembled DNS message.

### Clients (Connecting)

The users of the API calls ``isc_nm_udpconnect()``,
``isc_nm_streamdnsconnect()``, or ``isc_nm_httpconnect()`` with a connect
callback.

When connection is established, the connect callback is called with a handle and
status.

The connect callback should generally immediately call ``isc_nm_read()`` - see
the caveat in the previous parts.

After the connection has been connected, the read callback will receive exactly
1 call for each ``isc_nm_read()`` call - either with ``ISC_R_SUCCESS`` if the
DNS message was successfully read or non-``ISC_R_SUCCESS`` indicating the error
condition.  The read callback either needs to issue new ``isc_nm_read()`` call
or detach from the handle if no further messages are required.
