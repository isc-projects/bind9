# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

from collections.abc import (
    AsyncGenerator,
    Callable,
    Coroutine,
    Iterator,
    MutableSequence,
)
from dataclasses import dataclass, field
from typing import Any, Literal, cast

import abc
import asyncio
import collections
import functools
import logging
import os
import pathlib
import re
import signal
import sys

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.node
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.zone

import isctest.zone

from .context import DnsProtocol, Peer, QueryContext
from .dnssec import SigningKey
from .matchers import Always, Matcher

__all__ = [
    "AsyncDnsServer",
    "ConnectionHandler",
    "ControlCommand",
    "ControllableAsyncDnsServer",
    "DnsProtocol",
    "QueryContext",
    "ResponseAction",
    "ResponseHandler",
]

_UdpHandler = Callable[
    [bytes, tuple[str, int], asyncio.DatagramTransport], Coroutine[Any, Any, None]
]


_TcpHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, None]
]


class _AsyncUdpHandler(asyncio.DatagramProtocol):
    """
    Protocol implementation for handling UDP traffic using asyncio.
    """

    def __init__(
        self,
        handler: _UdpHandler,
    ) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._handler: _UdpHandler = handler

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Called by asyncio when a connection is made.
        """
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """
        Called by asyncio when a datagram is received.
        """
        assert self._transport
        handler_coroutine = self._handler(data, addr, self._transport)
        asyncio.create_task(handler_coroutine)


class _AsyncServer:
    """
    A generic asynchronous server which may handle UDP and/or TCP traffic.

    Once the server is executed as asyncio coroutine, it will keep running
    until a SIGINT/SIGTERM signal is received.
    """

    def __init__(
        self,
        udp_handler: _UdpHandler | None,
        tcp_handler: _TcpHandler | None,
        pidfile: str | None = None,
    ) -> None:
        logging.basicConfig(
            format="%(asctime)s %(levelname)8s  %(message)s",
            level=os.environ.get("ANS_LOG_LEVEL", "INFO").upper(),
        )
        try:
            ipv4_address = sys.argv[1]
        except IndexError:
            ipv4_address = self._get_ipv4_address_from_directory_name()

        last_ipv4_address_octet = ipv4_address.split(".")[-1]
        ipv6_address = f"fd92:7065:b8e:ffff::{last_ipv4_address_octet}"

        try:
            port = int(sys.argv[2])
        except IndexError:
            port = int(os.environ.get("PORT", 5300))

        logging.info("Setting up IPv4 listener at %s:%d", ipv4_address, port)
        logging.info("Setting up IPv6 listener at [%s]:%d", ipv6_address, port)

        self._ip_addresses: tuple[str, str] = (ipv4_address, ipv6_address)
        self._port: int = port
        self._udp_handler: _UdpHandler | None = udp_handler
        self._tcp_handler: _TcpHandler | None = tcp_handler
        self._pidfile: str | None = pidfile
        self._work_done: asyncio.Future | None = None

    def _get_ipv4_address_from_directory_name(self) -> str:
        containing_directory = pathlib.Path().absolute().stem
        match_result = re.match(r"ans(?P<index>\d+)", containing_directory)
        if not match_result:
            raise RuntimeError("Unable to auto-determine the IPv4 address to use")

        return f"10.53.0.{match_result.group('index')}"

    def run(self) -> None:
        """
        Start the server in an asynchronous coroutine.
        """
        asyncio.run(self._run())

    async def _run(self) -> None:
        self._setup_exception_handler()
        self._setup_signals()
        assert self._work_done
        await self._listen_udp()
        await self._listen_tcp()
        self._write_pidfile()
        await self._work_done
        self._cleanup_pidfile()

    def _setup_exception_handler(self) -> None:
        loop = asyncio.get_running_loop()
        self._work_done = loop.create_future()
        loop.set_exception_handler(self._handle_exception)

    def _handle_exception(
        self, _: asyncio.AbstractEventLoop, context: dict[str, Any]
    ) -> None:
        assert self._work_done
        exception = context.get("exception", RuntimeError(context["message"]))
        try:
            self._work_done.set_exception(exception)
        except asyncio.InvalidStateError:
            pass

    def _setup_signals(self) -> None:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, functools.partial(self._signal_done))
        loop.add_signal_handler(signal.SIGTERM, functools.partial(self._signal_done))

    def _signal_done(self) -> None:
        assert self._work_done
        try:
            self._work_done.set_result(True)
        except asyncio.InvalidStateError:
            pass

    async def _listen_udp(self) -> None:
        if not self._udp_handler:
            return
        loop = asyncio.get_running_loop()
        for ip_address in self._ip_addresses:
            await loop.create_datagram_endpoint(
                lambda: _AsyncUdpHandler(cast(_UdpHandler, self._udp_handler)),
                (ip_address, self._port),
            )

    async def _listen_tcp(self) -> None:
        if not self._tcp_handler:
            return
        for ip_address in self._ip_addresses:
            await asyncio.start_server(
                self._tcp_handler, host=ip_address, port=self._port
            )

    def _write_pidfile(self) -> None:
        if not self._pidfile:
            return
        logging.info("Writing PID to %s", self._pidfile)
        with open(self._pidfile, "w", encoding="ascii") as pidfile:
            print(f"{os.getpid()}", file=pidfile)

    def _cleanup_pidfile(self) -> None:
        if not self._pidfile:
            return
        logging.info("Removing %s", self._pidfile)
        os.unlink(self._pidfile)


@dataclass
class ResponseAction(abc.ABC):
    """
    Base class for actions that can be taken in response to a query.
    """

    @abc.abstractmethod
    async def perform(self) -> dns.message.Message | bytes | None:
        """
        This method is expected to carry out arbitrary actions (e.g. wait for a
        specific amount of time, modify the answer, etc.) and then return the
        DNS response to send (a dns.message.Message, a raw bytes object, or
        None, which prevents any response from being sent).
        """
        raise NotImplementedError


class _ConnectionTeardownRequested(Exception):
    pass


class ConnectionHandler(abc.ABC):
    """
    Base class for TCP connection handlers.

    An installed connection handler is called when a new TCP connection is
    established.  It may be used to perform arbitrary actions before
    AsyncDnsServer processes DNS queries.
    """

    @abc.abstractmethod
    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: Peer
    ) -> None:
        """
        Handle the connection with the provided reader and writer.
        """
        raise NotImplementedError


class ResponseHandler(abc.ABC):
    """
    Base class for generic response handlers.

    The queries a handler handles are declared in its `matcher`; the first
    handler whose matcher matches a query handles it, and response(s) may be
    generated by its `get_responses()` method.  The default matcher handles
    every query.
    """

    matcher: Matcher = Always()

    @abc.abstractmethod
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        """
        Custom handler which may produce response(s) to matching queries.

        The response prepared from zone data is passed to this method in
        qctx.response.
        """
        raise NotImplementedError
        yield  # pylint: disable=unreachable

    def __str__(self) -> str:
        if isinstance(self.matcher, Always):
            return self.__class__.__name__
        return f"{self.__class__.__name__} matching {self.matcher}"


@dataclass
class _ZoneTreeNode:
    """
    A node representing a zone with one origin.
    """

    zone: dns.zone.Zone | None
    children: list["_ZoneTreeNode"] = field(default_factory=list)


class _ZoneTree:
    """
    Tree with independent zones.

    This zone tree is used as a backing structure for the DNS server. The
    individual zones are independent to allow the (single) server to serve both
    the parent zone and a child zone if needed.
    """

    def __init__(self) -> None:
        self._root: _ZoneTreeNode = _ZoneTreeNode(None)

    def add(self, origin: dns.name.Name, zone: dns.zone.Zone) -> None:
        """
        Add a zone to the tree and rearrange sub-zones if necessary.
        """
        best_match = self._find_best_match(origin, self._root)
        added_node = _ZoneTreeNode(zone)
        self._move_children(best_match, added_node)
        best_match.children.append(added_node)

    def _find_best_match(
        self, name: dns.name.Name, start_node: _ZoneTreeNode
    ) -> _ZoneTreeNode:
        for child in start_node.children:
            assert child.zone
            assert child.zone.origin
            if name.is_subdomain(child.zone.origin):
                return self._find_best_match(name, child)
        return start_node

    def _move_children(self, node_from: _ZoneTreeNode, node_to: _ZoneTreeNode) -> None:
        assert node_to.zone
        assert node_to.zone.origin

        children_to_move = []
        for child in node_from.children:
            assert child.zone
            assert child.zone.origin
            if child.zone.origin.is_subdomain(node_to.zone.origin):
                children_to_move.append(child)

        for child in children_to_move:
            node_from.children.remove(child)
            node_to.children.append(child)

    def _find_best_zone_for_name(self, name: dns.name.Name) -> dns.zone.Zone | None:
        """
        Return the closest matching zone (if any) for the provided domain name.
        """
        node = self._find_best_match(name, self._root)
        return node.zone if node != self._root else None

    def find_best_zone(
        self, name: dns.name.Name, qtype: dns.rdatatype.RdataType
    ) -> dns.zone.Zone | None:
        """
        Return the zone (if any) from which to answer a <name, qtype> query.
        """
        if qtype == dns.rdatatype.DS and name != dns.name.root:
            # A DS query (other than ./DS) should be answered from the parent
            # side of the zone cut, but this server might not be hosting it.
            if parent_zone := self._find_best_zone_for_name(name.parent()):
                return parent_zone

        return self._find_best_zone_for_name(name)


_ASYNCSERVER_RESPONSE_MARKER = "__is_asyncserver_response__"


def _make_asyncserver_response(query: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(query)
    setattr(response, _ASYNCSERVER_RESPONSE_MARKER, True)
    return response


def _is_asyncserver_response(message: dns.message.Message) -> bool:
    return getattr(message, _ASYNCSERVER_RESPONSE_MARKER, False)


class AsyncDnsServer(_AsyncServer):
    """
    DNS server which responds to queries based on zone data and/or custom
    handlers.

    The server may use custom handlers which allow arbitrary query processing.
    These don't need to be standards-compliant and can be used for testing all
    sorts of scenarios, including delaying responses, synthesizing them based
    on query contents etc.

    The server also loads any zone files found in the zones/ subdirectory and
    serves them (*.db and *.db.signed files; if both exist for the same origin,
    only the signed variant is loaded). Responses prepared using zone data can
    then be modified, replaced, or suppressed by query handlers. Query handlers
    can also generate response from scratch, without using zone data at all.
    """

    def __init__(
        self,
        /,
        default_rcode: dns.rcode.Rcode = dns.rcode.REFUSED,
        default_aa: bool = False,
        keyring: dict[dns.name.Name, dns.tsig.Key] | Literal[False] | None = None,
        acknowledge_manual_dname_handling: bool = False,
    ) -> None:
        super().__init__(self._handle_udp, self._handle_tcp, "ans.pid")

        self._zone_tree: _ZoneTree = _ZoneTree()
        self._zones: dict[dns.name.Name, dns.zone.Zone] = {}
        self._keys: dict[dns.name.Name, MutableSequence[SigningKey]] = (
            collections.defaultdict(list)
        )
        self._connection_handler: ConnectionHandler | None = None
        self._response_handlers: list[ResponseHandler] = []
        self._default_rcode = default_rcode
        self._default_aa = default_aa
        self._keyring = keyring
        self._acknowledge_manual_dname_handling = acknowledge_manual_dname_handling

        self._load_zones()
        self._load_keys()

    def install_response_handler(
        self, handler: ResponseHandler, prepend: bool = False
    ) -> None:
        """
        Add a response handler that will be used to handle matching queries.

        Response handlers can modify, replace, or suppress the answers prepared
        from zone file contents.

        The provided handler is installed at the end of the response handler
        list unless `prepend` is set to True, in which case it is installed at
        the beginning of the response handler list.
        """
        logging.info("Installing response handler: %s", handler)
        if prepend:
            self._response_handlers.insert(0, handler)
        else:
            self._response_handlers.append(handler)

    def install_response_handlers(self, *handlers: ResponseHandler) -> None:
        for handler in handlers:
            self.install_response_handler(handler)

    def replace_response_handlers(self, *new_handlers: ResponseHandler) -> None:
        """
        Uninstall all currently installed handlers and install the provided ones.
        """
        logging.info("Uninstalling response handlers: %s", str(self._response_handlers))
        self._response_handlers.clear()
        self.install_response_handlers(*new_handlers)

    def uninstall_response_handler(self, handler: ResponseHandler) -> None:
        """
        Remove the specified handler from the list of response handlers.
        """
        logging.info("Uninstalling response handler: %s", handler)
        self._response_handlers.remove(handler)

    def install_connection_handler(self, handler: ConnectionHandler) -> None:
        """
        Install a connection handler that will be called when a new TCP
        connection is established.
        """
        if self._connection_handler:
            raise RuntimeError("Only one connection handler can be installed")
        self._connection_handler = handler

    def _scan_directory(self, directory: str) -> Iterator[os.DirEntry]:
        directory_path = pathlib.Path(directory)
        if directory_path.exists():
            yield from os.scandir(directory_path)

    def _is_preferred_zone_file(self, file: pathlib.Path) -> bool:
        if file.name.endswith(".db.signed"):
            return True
        if file.name.endswith(".db"):
            return not pathlib.Path(f"{file}.signed").exists()
        return False

    def _load_zones(self) -> None:
        for entry in self._scan_directory("zones/"):
            entry_path = pathlib.Path(entry.path)
            if not self._is_preferred_zone_file(entry_path):
                continue
            origin, zone = self._load_zone(entry_path)
            self._zone_tree.add(origin, zone)
            self._zones[origin] = zone

    def _load_zone(
        self, zone_file_path: pathlib.Path
    ) -> tuple[dns.name.Name, dns.zone.Zone]:
        logging.info("Loading zone file %s", zone_file_path)
        zone = self._load_zone_file(zone_file_path)
        self._abort_if_dname_found_unless_acknowledged(zone)
        assert zone.origin
        return zone.origin, zone

    def _load_zone_file(self, zone_file_path: pathlib.Path) -> dns.zone.Zone:
        try:
            zone = self._load_zone_file_with_origin(zone_file_path)
        except dns.zone.UnknownOrigin:
            zone = self._load_zone_file_without_origin(zone_file_path)

        return zone

    def _load_zone_file_with_origin(
        self, zone_file_path: pathlib.Path
    ) -> dns.zone.Zone:
        zone = dns.zone.from_file(str(zone_file_path), origin=None, relativize=False)
        if zone.origin != dns.name.root:
            error = "only the root zone may use $ORIGIN in the zone file; "
            error += "for every other zone, its origin is determined by "
            error += "the name of the file it is loaded from"
            raise ValueError(error)
        return zone

    def _load_zone_file_without_origin(
        self, zone_file_path: pathlib.Path
    ) -> dns.zone.Zone:
        origin = zone_file_path.name.removesuffix(".signed").removesuffix(".db")
        return dns.zone.from_file(str(zone_file_path), origin=origin, relativize=False)

    def _abort_if_dname_found_unless_acknowledged(self, zone: dns.zone.Zone) -> None:
        if self._acknowledge_manual_dname_handling:
            return

        error = f'DNAME records found in zone "{zone.origin}"; '
        error += "this server does not handle DNAME in a standards-compliant way; "
        error += "pass `acknowledge_manual_dname_handling=True` to the "
        error += "AsyncDnsServer constructor to acknowledge this and load zone anyway"

        for node in zone.nodes.values():
            for rdataset in node:
                if rdataset.rdtype == dns.rdatatype.DNAME:
                    raise ValueError(error)

    def _load_keys(self) -> None:
        for entry in self._scan_directory("keys/"):
            entry_path = pathlib.Path(entry.path)
            if entry_path.suffix != ".key":
                continue
            key = self._load_key(entry_path)
            self._keys[key.zone].append(key)

    def _load_key(self, key_file_path: pathlib.Path) -> SigningKey:
        zone = dns.name.from_text(key_file_path.stem.split("+")[0].removeprefix("K"))
        zone_key = isctest.zone.FileZoneKey(key_file_path.stem, key_file_path.parent)
        dnskey = zone_key.dnskey
        private_key = zone_key.private_key
        return SigningKey(zone=zone, dnskey=dnskey, private_key=private_key)

    async def _handle_udp(
        self, wire: bytes, addr: tuple[str, int], transport: asyncio.DatagramTransport
    ) -> None:
        logging.debug("Received UDP message: %s", wire.hex())
        socket_info = transport.get_extra_info("sockname")
        socket = Peer(socket_info[0], socket_info[1])
        peer = Peer(addr[0], addr[1])
        responses = self._handle_query(wire, socket, peer, DnsProtocol.UDP)
        async for response in responses:
            logging.debug("Sending UDP message: %s", response.hex())
            transport.sendto(response, addr)

    async def _handle_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_info = writer.get_extra_info("peername")
        peer = Peer(peer_info[0], peer_info[1])
        logging.debug("Accepted TCP connection from %s", peer)

        try:
            if self._connection_handler:
                await self._connection_handler.handle(reader, writer, peer)
            while True:
                wire = await self._read_tcp_query(reader, peer)
                if not wire:
                    break
                await self._send_tcp_response(writer, peer, wire)
        except _ConnectionTeardownRequested:
            pass
        except ConnectionResetError:
            logging.error("TCP connection from %s reset by peer", peer)
            return

        logging.debug("Closing TCP connection from %s", peer)
        writer.close()
        await writer.wait_closed()

    async def _read_tcp_query(
        self, reader: asyncio.StreamReader, peer: Peer
    ) -> bytes | None:
        wire_length = await self._read_tcp_query_wire_length(reader, peer)
        if not wire_length:
            return None

        return await self._read_tcp_query_wire(reader, peer, wire_length)

    async def _read_tcp_query_wire_length(
        self, reader: asyncio.StreamReader, peer: Peer
    ) -> int | None:
        logging.debug("Receiving TCP message length from %s...", peer)

        wire_length_bytes = await self._read_tcp_octets(reader, peer, 2)
        if not wire_length_bytes:
            return None

        return int.from_bytes(wire_length_bytes, byteorder="big")

    async def _read_tcp_query_wire(
        self, reader: asyncio.StreamReader, peer: Peer, wire_length: int
    ) -> bytes | None:
        logging.debug("Receiving TCP message (%d octets) from %s...", wire_length, peer)

        wire = await self._read_tcp_octets(reader, peer, wire_length)
        if not wire:
            return None

        logging.debug("Received complete TCP message from %s: %s", peer, wire.hex())

        return wire

    async def _read_tcp_octets(
        self, reader: asyncio.StreamReader, peer: Peer, expected: int
    ) -> bytes | None:
        buffer = b""

        while len(buffer) < expected:
            chunk = await reader.read(expected - len(buffer))
            if not chunk:
                if buffer:
                    logging.debug(
                        "Received short TCP message (%d octets) from %s: %s",
                        len(buffer),
                        peer,
                        buffer.hex(),
                    )
                else:
                    logging.debug("Received disconnect from %s", peer)
                return None

            logging.debug("Received %d TCP octets from %s", len(chunk), peer)
            buffer += chunk

        return buffer

    async def _send_tcp_response(
        self, writer: asyncio.StreamWriter, peer: Peer, wire: bytes
    ) -> None:
        socket_info = writer.get_extra_info("sockname")
        socket = Peer(socket_info[0], socket_info[1])
        responses = self._handle_query(wire, socket, peer, DnsProtocol.TCP)
        async for response in responses:
            logging.debug("Sending TCP response: %s", response.hex())
            writer.write(response)
            await writer.drain()

    def _log_query(self, qctx: QueryContext) -> None:
        logging.info(
            "Received %s/%s/%s (ID=%d) query from %s on %s (%s)",
            qctx.qname.to_text(omit_final_dot=True),
            dns.rdataclass.to_text(qctx.qclass),
            dns.rdatatype.to_text(qctx.qtype),
            qctx.query.id,
            qctx.peer,
            qctx.socket,
            qctx.protocol.name,
        )
        logging.debug(
            "\n".join([f"[IN] {l}" for l in [""] + str(qctx.query).splitlines()])
        )

    def _log_response(
        self, qctx: QueryContext, response: dns.message.Message | bytes | None
    ) -> None:
        if not response:
            logging.info(
                "Not sending a response to query (ID=%d) from %s on %s (%s)",
                qctx.query.id,
                qctx.peer,
                qctx.socket,
                qctx.protocol.name,
            )
            return

        if isinstance(response, dns.message.Message):
            try:
                qname = response.question[0].name.to_text(omit_final_dot=True)
                qclass = dns.rdataclass.to_text(response.question[0].rdclass)
                qtype = dns.rdatatype.to_text(response.question[0].rdtype)
            except IndexError:
                qname = "<empty>"
                qclass = "-"
                qtype = "-"

            logging.info(
                "Sending %s/%s/%s (ID=%d) response (%d/%d/%d/%d) to a query (ID=%d) from %s on %s (%s)",
                qname,
                qclass,
                qtype,
                response.id,
                len(response.question),
                len(response.answer),
                len(response.authority),
                len(response.additional),
                qctx.query.id,
                qctx.peer,
                qctx.socket,
                qctx.protocol.name,
            )
            try:
                response_text = str(response)
            except OverflowError:
                response_text = "<response not representable as text>"
            logging.debug(
                "\n".join([f"[OUT] {l}" for l in [""] + response_text.splitlines()])
            )
            return

        logging.info(
            "Sending response (%d bytes) to a query (ID=%d) from %s on %s (%s)",
            len(response),
            qctx.query.id,
            qctx.peer,
            qctx.socket,
            qctx.protocol.name,
        )
        logging.debug("[OUT] %s", response.hex())

    def _prepare_response_wire(
        self, qctx: QueryContext, response: dns.message.Message | bytes | None
    ) -> bytes | None:
        def prepend_length_unless_udp(payload: bytes) -> bytes:
            if qctx.protocol == DnsProtocol.UDP:
                return payload
            return len(payload).to_bytes(2, byteorder="big") + payload

        payload: bytes
        match response:
            case dns.message.Message(wire=bytes() as cached) if (
                response.tsig is not None
            ):
                # A TSIG-signed response is sent from its already-rendered wire
                # verbatim: re-rendering would generate a different signature and
                # break multi-message TSIG chaining (see xfer/ans5).
                payload = cached
            case dns.message.Message():
                # Otherwise the message object is the source of truth: render it
                # now so any change made after an earlier to_wire() render (a size
                # measurement, a relayed-then-edited response, a late AA or RCODE
                # change) reaches the wire.
                payload = response.to_wire(max_size=65535)
            case bytes():
                payload = response
            case _:
                return None
        return prepend_length_unless_udp(payload)

    async def _handle_query(
        self, wire: bytes, socket: Peer, peer: Peer, protocol: DnsProtocol
    ) -> AsyncGenerator[bytes, None]:
        """
        Yield wire data to send as a response over the established transport.
        """
        try:
            query = self._parse_message(wire)
        except dns.exception.DNSException as exc:
            logging.error("Invalid query from %s (%s): %s", peer, wire.hex(), exc)
            return
        response_stub = _make_asyncserver_response(query)
        keys = {k: tuple(v) for k, v in self._keys.items()}
        qctx = QueryContext(
            query, response_stub, self._zones, keys, socket, peer, protocol
        )
        self._log_query(qctx)
        responses = self._prepare_responses(qctx)
        async for response in responses:
            # Call _prepare_response_wire before logging the response, so that TSIG
            # records are properly included in the logged response.
            response_wire = self._prepare_response_wire(qctx, response)
            self._log_response(qctx, response)
            if response_wire is not None:
                yield response_wire

    def _parse_message(self, wire: bytes) -> dns.message.Message:
        try:
            return dns.message.from_wire(wire, keyring=self._keyring)
        except dns.message.UnknownTSIGKey as exc:
            if self._keyring is not None:
                raise
            error = "TSIG-signed query received but no `keyring` was provided; "
            error += "either provide a keyring (in which case the server will "
            error += "ignore any TSIG-invalid queries), or set `keyring=False` "
            error += "to disable TSIG validation altogether."
            raise ValueError(error) from exc

    async def _prepare_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[dns.message.Message | bytes | None, None]:
        """
        Yield response(s) either from response handlers or zone data.
        """
        qctx.response.set_rcode(self._default_rcode)
        if self._default_aa:
            qctx.response.flags |= dns.flags.AA
        qctx.save_initialized_response(with_zone_data=False)

        self._prepare_response_from_zone_data(qctx)
        qctx.save_initialized_response(with_zone_data=True)

        response_handled = False
        async for action in self._run_response_handlers(qctx):
            yield await action.perform()
            response_handled = True

        if not response_handled:
            logging.debug("Responding based on zone data")
            yield qctx.response

    def _prepare_response_from_zone_data(self, qctx: QueryContext) -> None:
        """
        Prepare a response to the query based on the available zone data.

        The functionality is split across smaller functions that modify the
        query context until a proper response is formed.
        """
        if self._refused_response(qctx):
            return

        if self._delegation_response(qctx):
            return

        qctx.response.flags |= dns.flags.AA

        if self._ent_response(qctx):
            return

        if self._nxdomain_response(qctx):
            return

        if self._cname_response(qctx):
            return

        if self._nodata_response(qctx):
            return

        self._noerror_response(qctx)

    def _refused_response(self, qctx: QueryContext) -> bool:
        zone = self._zone_tree.find_best_zone(qctx.current_qname, qctx.qtype)
        if zone:
            qctx.zone = zone
            return False

        # RCODE is already set to self._default_rcode, i.e. REFUSED by default;
        # it should also not be changed when following a CNAME chain
        return True

    def _delegation_response(self, qctx: QueryContext) -> bool:
        assert qctx.zone

        name = qctx.current_qname
        ns_rdataset = None

        while name != qctx.zone.origin:
            if node := qctx.zone.get_node(name):
                if ns_rdataset := node.get_rdataset(qctx.qclass, dns.rdatatype.NS):
                    break
            name = name.parent()

        if not ns_rdataset:
            return False

        # Only answer DS queries for the delegation point itself; return a
        # referral for anything below the delegation point.
        if qctx.qtype == dns.rdatatype.DS and name == qctx.current_qname:
            return False

        ns_rrset = dns.rrset.RRset(name, qctx.qclass, dns.rdatatype.NS)
        ns_rrset.update(ns_rdataset)

        qctx.response.set_rcode(dns.rcode.NOERROR)
        qctx.response.authority.append(ns_rrset)

        if qctx.query.ednsflags & dns.flags.DO:
            assert node
            if ds_rdataset := node.get_rdataset(qctx.qclass, dns.rdatatype.DS):
                ds_rrset = dns.rrset.RRset(name, qctx.qclass, dns.rdatatype.DS)
                ds_rrset.update(ds_rdataset)

                rrsig_rrset = qctx.get_rrsig(ds_rrset, node=node)
                assert rrsig_rrset

                qctx.response.authority.append(ds_rrset)
                qctx.response.authority.append(rrsig_rrset)
            elif next(qctx.zone.iterate_rdatasets(dns.rdatatype.DNSKEY), None):
                qctx.nsecx.prove_no_ds(name)

        self._delegation_response_additional(qctx)

        return True

    def _delegation_response_additional(self, qctx: QueryContext) -> None:
        assert qctx.zone

        ns_rrset = next(
            (r for r in qctx.response.authority if r.rdtype == dns.rdatatype.NS), None
        )
        if not ns_rrset:
            return

        for nameserver in ns_rrset:
            if not nameserver.target.is_subdomain(ns_rrset.name):
                continue
            for rdtype in dns.rdatatype.A, dns.rdatatype.AAAA:
                if glue := qctx.zone.get_rrset(nameserver.target, rdtype):
                    qctx.response.additional.append(glue)

    def _name_exists(self, qctx: QueryContext, name: dns.name.Name) -> bool:
        assert qctx.zone
        return qctx.zone.get_node(name) is not None or any(
            n.is_subdomain(name) for n in qctx.zone.nodes
        )

    def _ent_response(self, qctx: QueryContext) -> bool:
        assert qctx.zone
        assert qctx.zone.origin

        qctx.soa = qctx.zone.get_rrset(qctx.zone.origin, dns.rdatatype.SOA)
        assert qctx.soa

        qctx.node = qctx.zone.get_node(qctx.current_qname)
        if qctx.node or not self._name_exists(qctx, qctx.current_qname):
            return False

        qctx.response.set_rcode(dns.rcode.NOERROR)
        qctx.response.authority.append(qctx.soa)
        if soa_rrsig := qctx.get_rrsig(qctx.soa):
            qctx.response.authority.append(soa_rrsig)
            qctx.nsecx.prove_ent()
        return True

    def _match_wildcard(self, qctx: QueryContext) -> dns.node.Node | None:
        assert qctx.zone

        closest_encloser = qctx.current_qname.parent()
        while not self._name_exists(qctx, closest_encloser):
            closest_encloser = closest_encloser.parent()

        wildcard_owner = dns.name.from_text("*", origin=closest_encloser)
        return qctx.zone.get_node(wildcard_owner)

    def _nxdomain_response(self, qctx: QueryContext) -> bool:
        assert qctx.soa

        qctx.node = qctx.node or self._match_wildcard(qctx)
        if qctx.node:
            return False

        qctx.response.set_rcode(dns.rcode.NXDOMAIN)
        qctx.response.authority.append(qctx.soa)
        if soa_rrsig := qctx.get_rrsig(qctx.soa):
            qctx.response.authority.append(soa_rrsig)
            qctx.nsecx.prove_nxdomain()

        return True

    def _cname_response(self, qctx: QueryContext) -> bool:
        assert qctx.node

        cname = qctx.node.get_rdataset(qctx.qclass, dns.rdatatype.CNAME)
        if not cname:
            return False

        qctx.response.set_rcode(dns.rcode.NOERROR)
        cname_rrset = dns.rrset.RRset(qctx.current_qname, qctx.qclass, cname.rdtype)
        cname_rrset.update(cname)
        qctx.response.answer.append(cname_rrset)
        if cname_rrsig := qctx.get_rrsig(cname_rrset):
            qctx.response.answer.append(cname_rrsig)

        qctx.alias = cname[0].target
        self._prepare_response_from_zone_data(qctx)
        return True

    def _nodata_response(self, qctx: QueryContext) -> bool:
        assert qctx.node
        assert qctx.soa

        qctx.answer = qctx.node.get_rdataset(qctx.qclass, qctx.qtype)
        if qctx.answer:
            return False

        qctx.response.set_rcode(dns.rcode.NOERROR)
        qctx.response.authority.append(qctx.soa)
        if soa_rrsig := qctx.get_rrsig(qctx.soa):
            qctx.response.authority.append(soa_rrsig)
            qctx.nsecx.prove_nodata()
        return True

    def _noerror_response(self, qctx: QueryContext) -> None:
        assert qctx.answer

        answer_rrset = dns.rrset.RRset(qctx.current_qname, qctx.qclass, qctx.qtype)
        answer_rrset.update(qctx.answer)

        qctx.response.set_rcode(dns.rcode.NOERROR)
        qctx.response.answer.append(answer_rrset)
        if answer_rrsig := qctx.get_rrsig(answer_rrset):
            qctx.response.answer.append(answer_rrsig)
            qctx.nsecx.prove_noerror()

    async def _run_response_handlers(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        """
        Yield response(s) to the query from a matching query handler.
        """
        for handler in self._response_handlers:
            if handler.matcher.match(qctx):
                logging.debug("Matched response handler: %s", handler)
                async for response in handler.get_responses(qctx):
                    yield response
                return


class ControllableAsyncDnsServer(AsyncDnsServer):
    """
    An AsyncDnsServer whose behavior can be dynamically changed by sending TXT
    queries to a "magic" domain.
    """

    _CONTROL_DOMAIN = "_control."

    @functools.cached_property
    def _control_domain(self) -> dns.name.Name:
        return dns.name.from_text(self._CONTROL_DOMAIN)

    @functools.cached_property
    def _commands(self) -> dict[dns.name.Name, "ControlCommand"]:
        return {}

    def install_control_commands(self, *commands: "ControlCommand") -> None:
        for command in commands:
            self.install_control_command(command)

    def install_control_command(self, command: "ControlCommand") -> None:
        command_subdomain = dns.name.Name([command.control_subdomain])
        control_subdomain = command_subdomain.concatenate(self._control_domain)
        try:
            existing_command = self._commands[control_subdomain]
        except KeyError:
            self._commands[control_subdomain] = command
        else:
            raise RuntimeError(
                f"{control_subdomain} already handled by {existing_command}"
            )

    async def _prepare_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[dns.message.Message | bytes | None, None]:
        """
        Detect and handle control queries, falling back to normal processing
        for non-control queries.
        """
        control_response = self._handle_control_command(qctx)
        if control_response:
            yield control_response
            return

        async for response in super()._prepare_responses(qctx):
            yield response

    def _handle_control_command(self, qctx: QueryContext) -> dns.message.Message | None:
        """
        Detect and handle control queries.

        A control query must be of type TXT; if it is not, a FORMERR response
        is sent back.

        The list of commands that the server should respond to is passed to its
        constructor.  If the server is unable to handle the control query using
        any of the enabled commands, an NXDOMAIN response is sent.

        Otherwise, the relevant command's handler is expected to provide the
        response via qctx.response and/or return a string that is converted to
        a TXT RRset inserted into the ANSWER section of the response to the
        control query.  The RCODE for a command-provided response defaults to
        NOERROR, but can be overridden by the command's handler.
        """
        if not qctx.qname.is_subdomain(self._control_domain):
            return None

        if qctx.qtype != dns.rdatatype.TXT:
            logging.error("Non-TXT control query %s from %s", qctx.qname, qctx.peer)
            qctx.response.set_rcode(dns.rcode.FORMERR)
            return qctx.response

        control_subdomain = dns.name.Name(qctx.qname.labels[-3:])
        try:
            command = self._commands[control_subdomain]
        except KeyError:
            logging.error("Unhandled control query %s from %s", qctx.qname, qctx.peer)
            qctx.response.set_rcode(dns.rcode.NXDOMAIN)
            return qctx.response

        logging.info("Received control query %s from %s", qctx.qname, qctx.peer)
        logging.debug("Handling control query %s using %s", qctx.qname, command)
        qctx.response.set_rcode(dns.rcode.NOERROR)
        qctx.response.flags |= dns.flags.AA

        command_qname = qctx.qname.relativize(control_subdomain)
        try:
            command_args = [l.decode("ascii") for l in command_qname.labels]
        except UnicodeDecodeError:
            logging.error("Non-ASCII control query %s from %s", qctx.qname, qctx.peer)
            qctx.response.set_rcode(dns.rcode.FORMERR)
            return qctx.response

        command_response = command.handle(command_args, self, qctx)
        if command_response:
            command_response_rrset = dns.rrset.from_text(
                qctx.qname, 0, qctx.qclass, dns.rdatatype.TXT, f'"{command_response}"'
            )
            qctx.response.answer.append(command_response_rrset)

        return qctx.response


class ControlCommand(abc.ABC):
    """
    Base class for control commands.

    The derived class must define the control query subdomain that it handles
    and the callback that handles the control queries.
    """

    @property
    @abc.abstractmethod
    def control_subdomain(self) -> str:
        """
        The subdomain of the control domain handled by this command.  Needs to
        be defined as a string by the derived class.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def handle(
        self, args: list[str], server: ControllableAsyncDnsServer, qctx: QueryContext
    ) -> str | None:
        """
        This method is expected to carry out arbitrary actions in response to a
        control query.  Note that it is invoked synchronously (it is not a
        coroutine).

        `args` is a list of arguments for the command extracted from the
        control query's QNAME; these arguments (and therefore the QNAME as
        well) must only contain ASCII characters.  For example, if a command's
        subdomain is `my-command`, control query `foo.bar.my-command._control.`
        causes `args` to be set to `["foo", "bar"]` while control query
        `my-command._control.` causes `args` to be set to `[]`.

        `server` is the server instance that received the control query.  This
        method can change the server's behavior by altering its response
        handler list using the appropriate methods.

        `qctx` is the query context for the control query.  By operating on
        qctx.response, this method can prepare the DNS response sent to
        the client in response to the control query.  Alternatively (or in
        addition to the above), it can also return a string; if it does, the
        returned string is converted to a TXT RRset that is inserted into the
        ANSWER section of the response to the control query.
        """
        raise NotImplementedError

    def __str__(self) -> str:
        return self.__class__.__name__
