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

from collections.abc import AsyncGenerator, Collection, Sequence
from dataclasses import dataclass, field
from typing import cast, final

import abc
import asyncio
import logging

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from . import (
    ConnectionHandler,
    ResponseAction,
    ResponseHandler,
    _ConnectionTeardownRequested,
)
from .actions import BytesResponseSend, DnsResponseSend, ResponseDrop
from .context import Peer, QueryContext


def block_reading(peer: Peer, writer_not_the_reader: asyncio.StreamWriter) -> None:
    """
    Block reads for the reader associated with the provided writer.

    Yes, pass the writer, not the reader. See the comments below for details.
    """

    loop = asyncio.get_running_loop()

    logging.info("Blocking reads from %s", peer)

    # This is Michał's submission for the Ugliest Hack of the Year contest.
    # (The alternative was implementing an asyncio transport from scratch.)
    #
    # In order to prevent the client socket from being read from, simply
    # not calling `reader.read()` is not enough, because asyncio buffers
    # incoming data itself on the transport level.  However, `StreamReader`
    # does not expose the underlying transport as a property.  Therefore,
    # cheat by extracting it from `StreamWriter` as it is the same
    # bidirectional transport as for the read side (a `Transport`, which is
    # a subclass of both `ReadTransport` and `WriteTransport`) and call
    # `ReadTransport.pause_reading()` to remove the underlying socket from
    # the set of descriptors monitored by the selector, thereby preventing
    # any reads from happening on the client socket.  However...
    loop.call_soon(writer_not_the_reader.transport.pause_reading)  # type: ignore

    # ...due to `AsyncDnsServer._handle_tcp()` being a coroutine, by the
    # time it gets executed, asyncio transport code will already have added
    # the client socket to the set of descriptors monitored by the
    # selector.  Therefore, if the client starts sending data immediately,
    # a read from the socket will have already been scheduled by the time
    # this handler gets executed.  There is no way to prevent that from
    # happening, so work around it by abusing the fact that the transport
    # at hand is specifically an instance of `_SelectorSocketTransport`
    # (from asyncio.selector_events) and set the size of its read buffer to
    # just a single byte.  This does give asyncio enough time to read that
    # single byte from the client socket's buffer before that socket is
    # removed from the set of monitored descriptors, but prevents the
    # one-off read from emptying the client socket buffer _entirely_, which
    # is enough to trigger sending an RST segment when the connection is
    # closed shortly afterwards.
    writer_not_the_reader.transport.max_size = 1  # type: ignore


@dataclass
class IgnoreAllConnections(ConnectionHandler):
    """
    A connection handler that makes the server not read anything from the
    client socket, effectively ignoring all incoming connections.
    """

    _connections: set[asyncio.StreamWriter] = field(default_factory=set)

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: Peer
    ) -> None:
        block_reading(peer, writer)
        # Due to the way various asyncio-related objects (tasks, streams,
        # transports, selectors) are referencing each other, pausing reads for
        # a TCP transport (which in practice means removing the client socket
        # from the set of descriptors monitored by a selector) can cause the
        # client task (AsyncDnsServer._handle_tcp()) to be prematurely
        # garbage-collected, causing asyncio code to raise a "Task was
        # destroyed but it is pending!" exception.  Prevent that from happening
        # by keeping a reference to each incoming TCP connection to protect its
        # related asyncio objects from getting garbage-collected.  This
        # prevents AsyncDnsServer from closing any of the ignored TCP
        # connections indefinitely, which is obviously a pretty brain-dead idea
        # for a production-grade DNS server, but AsyncDnsServer was never meant
        # to be one and this hack reliably solves the problem at hand.
        self._connections.add(writer)


@dataclass
class ConnectionReset(ConnectionHandler):
    """
    A connection handler that makes the server close the connection without
    reading anything from the client socket.

    The connection may be closed with a delay if requested.

    The sole purpose of this handler is to trigger a connection reset, i.e. to
    make the server send an RST segment; this happens when the server closes a
    client's socket while there is still unread data in that socket's buffer.
    If closing the connection _after_ the query is read by the server is enough
    for a given use case, the CloseConnection response handler should be used
    instead.
    """

    delay: float = 0.0

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: Peer
    ) -> None:
        block_reading(peer, writer)

        if self.delay > 0:
            logging.info(
                "Waiting %.1fs before closing TCP connection from %s", self.delay, peer
            )
            await asyncio.sleep(self.delay)

        raise _ConnectionTeardownRequested


class ResponseHandlerWrapper(ResponseHandler, abc.ABC):
    """
    Base class for handlers that wrap another handler and modify each response
    it yields.  `match()` and the response stream are delegated to the wrapped
    `inner` handler; subclasses implement `_modify_response()` to mutate each
    yielded action in place, and may override `_on_query_received()` to reset
    per-query state.
    """

    def __init__(self, inner: ResponseHandler) -> None:
        self._inner = inner

    def match(self, qctx: QueryContext) -> bool:
        return self._inner.match(qctx)

    def _on_query_received(self, qctx: QueryContext) -> None:
        pass

    @abc.abstractmethod
    def _modify_response(
        self, qctx: QueryContext, response_action: ResponseAction
    ) -> None:
        raise NotImplementedError

    @final
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        self._on_query_received(qctx)
        async for response_action in self._inner.get_responses(qctx):
            self._modify_response(qctx, response_action)
            yield response_action

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self._inner})"


class IgnoreAllQueries(ResponseHandler):
    """
    Do not respond to any queries sent to the server.
    """

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseDrop, None]:
        yield ResponseDrop()


class QnameHandler(ResponseHandler):
    """
    Base class used for deriving custom QNAME handlers.

    The derived class must specify a list of `qnames` that it wants to handle.
    Queries for exactly these QNAMEs will then be passed to the
    `get_response()` method in the derived class.
    """

    @property
    @abc.abstractmethod
    def qnames(self) -> list[str]:
        """
        A list of QNAMEs handled by this class.
        """
        raise NotImplementedError

    def __init__(self) -> None:
        self._qnames: list[dns.name.Name] = [dns.name.from_text(d) for d in self.qnames]

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(QNAMEs: {', '.join(self.qnames)})"

    def match(self, qctx: QueryContext) -> bool:
        """
        Handle queries whose QNAME matches any of the QNAMEs handled by this
        class.
        """
        return qctx.qname in self._qnames


class QnameQtypeHandler(QnameHandler):
    """
    Handle queries for which both of the following conditions are true:

    - the query's QNAME is present in `self.qnames`,
    - the query's QTYPE is present in `self.qtypes`.
    """

    @property
    @abc.abstractmethod
    def qtypes(self) -> list[dns.rdatatype.RdataType]:
        """
        A list of QTYPEs handled by this class.
        """
        raise NotImplementedError

    def __init__(self) -> None:
        super().__init__()
        self._qtypes: list[dns.rdatatype.RdataType] = self.qtypes

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(QNAMEs: {', '.join(self.qnames)}; QTYPEs: {', '.join(map(str, self.qtypes))})"

    def match(self, qctx: QueryContext) -> bool:
        """
        Handle queries whose QNAME and QTYPE match any of the QNAMEs and
        QTYPEs handled by this class.
        """
        return qctx.qtype in self._qtypes and super().match(qctx)


class _UnsetEdnsType:
    pass


class StaticResponseHandler(ResponseHandler):
    """
    Base class used for deriving custom static response handlers.

    The derived class can specify the RRsets to be included in the answer,
    authority, and additional sections of the response, whether to set the AA
    bit in the response, and a delay before sending the response.

    The default implementation of `get_responses()` uses these properties to
    prepare and yield a single response.
    """

    @property
    def rcode(self) -> dns.rcode.Rcode | None:
        """
        Optional RCODE to be set in the response.
        """
        return None

    @property
    def answer(self) -> Sequence[dns.rrset.RRset]:
        """
        RRsets to be included in the answer section of the response.
        """
        return []

    @property
    def authority(self) -> Sequence[dns.rrset.RRset]:
        """
        RRsets to be included in the authority section of the response.
        """
        return []

    @property
    def additional(self) -> Sequence[dns.rrset.RRset]:
        """
        RRsets to be included in the additional section of the response.
        """
        return []

    @property
    def authoritative(self) -> bool | None:
        """
        Whether to set the AA bit in the response.
        """
        return None

    @property
    def delay(self) -> float:
        """
        Delay before sending the response.
        """
        return 0.0

    @property
    def edns(self) -> int | bool | None | _UnsetEdnsType:
        """
        Value passed to the response's ``use_edns()``.  Left unset by default,
        so EDNS is untouched; set it to anything ``use_edns()`` accepts (e.g.
        ``None`` to strip EDNS and mimic a non-EDNS server).
        """
        return _UnsetEdnsType()

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.answer.extend(self.answer)
        qctx.response.authority.extend(self.authority)
        qctx.response.additional.extend(self.additional)
        if self.rcode is not None:
            qctx.response.set_rcode(self.rcode)
        if not isinstance(self.edns, _UnsetEdnsType):
            qctx.response.use_edns(self.edns)
        yield DnsResponseSend(
            qctx.response, authoritative=self.authoritative, delay=self.delay
        )


class DomainHandler(ResponseHandler):
    """
    Base class used for deriving custom domain handlers.

    The derived class must specify a list of `domains` that it wants to handle.
    Queries for any of these domains (and their subdomains) will then be passed
    to the `get_response()` method in the derived class.

    The most specific matching domain is stored in the `matched_domain` attribute.
    """

    @property
    @abc.abstractmethod
    def domains(self) -> list[str]:
        """
        A list of domain names handled by this class.
        """
        raise NotImplementedError

    def __init__(self) -> None:
        self._domains: list[dns.name.Name] = sorted(
            [dns.name.from_text(d) for d in self.domains], reverse=True
        )
        self._matched_domain: dns.name.Name | None = None

    @property
    def matched_domain(self) -> dns.name.Name:
        assert self._matched_domain is not None
        return self._matched_domain

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(domains: {', '.join(self.domains)})"

    def match(self, qctx: QueryContext) -> bool:
        """
        Handle queries whose QNAME matches any of the domains handled by this
        class.
        """
        self._matched_domain = None
        for domain in self._domains:
            if qctx.qname.is_subdomain(domain):
                self._matched_domain = domain
                return True
        return False


class ForwarderHandler(ResponseHandler):
    """
    A handler forwarding all received queries to another DNS server with an
    optional delay and then relaying the responses back to the original client.

    Queries are currently always forwarded via UDP.
    """

    @property
    @abc.abstractmethod
    def target(self) -> str:
        """
        The address of the DNS server to forward queries to.
        """
        raise NotImplementedError

    @property
    def port(self) -> int:
        """
        The port of the DNS server to forward queries to.

        The default value of 0 causes the same port as the one used by this
        server for listening to be used.
        """
        return 0

    @property
    def delay(self) -> float:
        """
        The number of seconds to wait before forwarding each query.
        """
        return 0.0

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(target: {self.target}:{self.port})"

    class ForwarderProtocol(asyncio.DatagramProtocol):
        def __init__(self, query: bytes, response: asyncio.Future) -> None:
            self._query = query
            self._response = response

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            logging.debug("[OUT] %s", self._query.hex())
            cast(asyncio.DatagramTransport, transport).sendto(self._query)

        def datagram_received(self, data: bytes, _: tuple[str, int]) -> None:
            logging.debug("[IN] %s", data.hex())
            self._response.set_result(data)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[BytesResponseSend | DnsResponseSend, None]:
        loop = asyncio.get_running_loop()
        response = loop.create_future()
        forwarding_target = f"{self.target}:{self.port or qctx.socket.port}"

        if self.delay > 0:
            logging.info(
                "Waiting %.1fs before forwarding %s query from %s to %s over UDP",
                self.delay,
                qctx.protocol.name,
                qctx.peer,
                forwarding_target,
            )
            await asyncio.sleep(self.delay)

        logging.info(
            "Forwarding %s query from %s to %s over UDP",
            qctx.protocol.name,
            qctx.peer,
            forwarding_target,
        )

        transport, _ = await loop.create_datagram_endpoint(
            lambda: self.ForwarderProtocol(qctx.query.to_wire(), response),
            local_addr=(qctx.socket.host, 0),
            remote_addr=(self.target, self.port or qctx.socket.port),
        )

        try:
            await response
        finally:
            transport.close()

        logging.info(
            "Relaying UDP response from %s to %s over %s",
            forwarding_target,
            qctx.peer,
            qctx.protocol.name,
        )

        try:
            message = dns.message.from_wire(response.result(), keyring=False)
            yield DnsResponseSend(message, acknowledge_hand_rolled_response=True)
        except dns.exception.DNSException:
            logging.warning(
                "Failed to parse response from %s as a DNS message, relaying it as raw bytes",
                forwarding_target,
            )
            yield BytesResponseSend(response.result())


class AxfrHandler(ResponseHandler):
    """
    Base class for AXFR response handlers.

    Subclasses must define the `initial_soa`, `zone_contents`, and `final_soa`
    properties to specify the content of the AXFR responses.

    The responses are constructed without any regard to zone data.
    """

    @property
    @abc.abstractmethod
    def initial_soa(self) -> dns.rrset.RRset:
        """
        Initial SOA record of response packets sent in response to
        AXFR queries.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def zone_contents(self) -> Collection[dns.rrset.RRset]:
        """
        Answer section of the second response packet sent in response to
        AXFR queries.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def final_soa(self) -> dns.rrset.RRset:
        """
        Final SOA record of response packets sent in response to
        AXFR queries.
        """
        raise NotImplementedError

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.AXFR

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.answer.append(self.initial_soa)
        yield DnsResponseSend(qctx.response)

        qctx.prepare_new_response(with_zone_data=False)
        for rrset_ in self.zone_contents:
            qctx.response.answer.append(rrset_)
        yield DnsResponseSend(qctx.response)

        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.answer.append(self.final_soa)
        yield DnsResponseSend(qctx.response)
