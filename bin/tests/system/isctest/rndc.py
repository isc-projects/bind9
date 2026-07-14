# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

"""
This module implements the RNDC control protocol.
"""

from typing import Any

import base64
import hashlib
import hmac
import random
import socket
import struct
import time


class rndc:
    """RNDC protocol client library"""

    _algos = {
        "md5": 157,
        "sha1": 161,
        "sha224": 162,
        "sha256": 163,
        "sha384": 164,
        "sha512": 165,
    }

    def __init__(self, host: tuple[str, int], algo: str, secret: str) -> None:
        """Creates a persistent connection to RNDC and logs in
        host - (ip, port) tuple
        algo - HMAC algorithm, one of md5, sha1, sha224, sha256, sha384, sha512
        secret - HMAC secret, base64 encoded"""
        self.host = host
        self.algo = algo
        self.hlalgo = getattr(hashlib, algo)
        self.secret = base64.b64decode(secret)
        self.ser = random.randint(0, 1 << 24)
        self.nonce: bytes | None = None
        self._connect_login()

    def call(self, cmd: bytes) -> dict[bytes, bytes]:
        """Call a RNDC command, all parsing is done on the server side
        cmd - a complete command as bytes (eg b'reload zone example.com')
        """
        return dict(self._command({b"type": cmd})[b"_data"])

    def _serialize_dict(
        self, data: dict[bytes, Any], ignore_auth: bool = False
    ) -> bytes:
        rv = b""
        for k, v in data.items():
            if ignore_auth and k == b"_auth":
                continue
            rv += bytes([len(k)])
            rv += k
            if isinstance(v, bytes):
                rv += struct.pack(">BI", 1, len(v)) + v
            elif isinstance(v, dict):
                sd = self._serialize_dict(v)
                rv += struct.pack(">BI", 2, len(sd)) + sd
            else:
                raise NotImplementedError(f"Cannot serialize element of type {type(v)}")
        return rv

    def _prep_message(self, data: dict[bytes, Any]) -> bytes:
        self.ser += 1
        now = int(time.time())

        d: dict[bytes, Any] = {}
        d[b"_auth"] = {}
        d[b"_ctrl"] = {}
        d[b"_ctrl"][b"_ser"] = b"%d" % self.ser
        d[b"_ctrl"][b"_tim"] = b"%d" % now
        d[b"_ctrl"][b"_exp"] = b"%d" % (now + 60)
        if self.nonce is not None:
            d[b"_ctrl"][b"_nonce"] = self.nonce
        d[b"_data"] = data

        msg = self._serialize_dict(d, ignore_auth=True)
        digest = hmac.new(self.secret, msg, self.hlalgo).digest()
        bhash = base64.b64encode(digest)
        if self.algo == "md5":
            d[b"_auth"][b"hmd5"] = struct.pack("22s", bhash)
        else:
            d[b"_auth"][b"hsha"] = struct.pack("B88s", self._algos[self.algo], bhash)
        msg = self._serialize_dict(d)
        msg = struct.pack(">II", len(msg) + 4, 1) + msg
        return msg

    def _verify_msg(self, msg: dict[bytes, Any]) -> bool:
        if self.nonce is not None and msg[b"_ctrl"][b"_nonce"] != self.nonce:
            return False
        bhash = msg[b"_auth"][b"hmd5" if self.algo == "md5" else b"hsha"]
        bhash += b"=" * (4 - (len(bhash) % 4))
        remote_hash = base64.b64decode(bhash)
        my_msg = self._serialize_dict(msg, ignore_auth=True)
        my_hash = hmac.new(self.secret, my_msg, self.hlalgo).digest()
        return my_hash == remote_hash

    def _command(self, data: dict[bytes, Any]) -> dict[bytes, Any]:
        msg = self._prep_message(data)
        sent = self.socket.send(msg)
        if sent != len(msg):
            raise OSError("Cannot send the message")

        header = self.socket.recv(8)
        if len(header) != 8:
            # What should we throw here? Bad auth can cause this...
            raise OSError("Can't read response header")

        length, version = struct.unpack(">II", header)
        if version != 1:
            raise NotImplementedError(f"Wrong message version {version}")

        # it includes the header
        length -= 4
        payload = self.socket.recv(length, socket.MSG_WAITALL)
        if len(payload) != length:
            raise OSError("Can't read response data")

        response = self._parse_message(payload)
        if not self._verify_msg(response):
            raise OSError("Authentication failure")

        return response

    def _connect_login(self) -> None:
        self.socket = socket.create_connection(self.host)
        self.nonce = None
        msg = self._command({b"type": b"null"})
        self.nonce = msg[b"_ctrl"][b"_nonce"]

    def _parse_element(self, buf: bytes) -> tuple[bytes, Any, bytes]:
        pos = 0
        labellen = buf[pos]
        pos += 1
        label = buf[pos : pos + labellen]
        pos += labellen
        etype = buf[pos]
        pos += 1
        datalen = struct.unpack(">I", buf[pos : pos + 4])[0]
        pos += 4
        data = buf[pos : pos + datalen]
        pos += datalen
        rest = buf[pos:]

        if etype == 1:  # raw binary value
            return label, data, rest
        elif etype == 2:  # dictionary
            d: dict[bytes, Any] = {}
            while len(data) > 0:
                ilabel, value, data = self._parse_element(data)
                d[ilabel] = value
            return label, d, rest
        # TODO type 3 - list
        else:
            raise NotImplementedError(f"Unknown element type {etype}")

    def _parse_message(self, buf: bytes) -> dict[bytes, Any]:
        rv: dict[bytes, Any] = {}
        while len(buf) > 0:
            label, value, buf = self._parse_element(buf)
            rv[label] = value
        return rv
