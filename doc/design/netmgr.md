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

## UDP listening

UDP listener sockets automatically create an array of 'child' sockets,
each associated with one networker, and all listening on the same address
via `SO_REUSEADDR`.  (The parent's reference counter is used for all the
parent and child sockets together; none are destroyed until there are no
remaining references to any of tem.)

## TCP listening

A TCP listener socket cannot listen on multiple threads in parallel,
so receiving a TCP connection can cause a context switch, but this is
expected to be rare enough not to impact performance significantly.

When connected, a TCP socket will attach to the system-wide TCP clients
quota.

## TCP listening for DNS

A TCPDNS listener is a wrapper around a TCP socket which specifically
handles DNS traffic, including the two-byte length field that prepends DNS
messages over TCP.

Other wrapper socket types can be added in the future, such as a TLS socket
wrapper to implement encryption or an HTTP wrapper to implement the HTTP
protocol. This will enable the system to have a transport-neutral network
manager socket over which DNS can be sent without knowing anything about
transport, encryption, etc.
