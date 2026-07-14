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

import time
import struct
import hashlib
import hmac
import base64
import random
import socket


class rndc:
    """RNDC protocol client library"""

    __algos = {
        "md5": 157,
        "sha1": 161,
        "sha224": 162,
        "sha256": 163,
        "sha384": 164,
        "sha512": 165,
    }

    def __init__(self, host, algo, secret):
        """Creates a persistent connection to RNDC and logs in
        host - (ip, port) tuple
        algo - HMAC algorithm, one of md5, sha1, sha224, sha256, sha384, sha512
        secret - HMAC secret, base64 encoded"""
        self.host = host
        self.algo = algo
        self.hlalgo = getattr(hashlib, algo)
        self.secret = base64.b64decode(secret)
        self.ser = random.randint(0, 1 << 24)
        self.nonce = None
        self.__connect_login()

    def call(self, cmd):
        """Call a RNDC command, all parsing is done on the server side
        cmd - a complete command as bytes (eg b'reload zone example.com')
        """
        return dict(self.__command({b"type": cmd})[b"_data"])

    def __serialize_dict(self, data, ignore_auth=False):
        rv = b""
        for k, v in data.items():
            if ignore_auth and k == b"_auth":
                continue
            rv += bytes([len(k)])
            rv += k
            if isinstance(v, bytes):
                rv += struct.pack(">BI", 1, len(v)) + v
            elif isinstance(v, dict):
                sd = self.__serialize_dict(v)
                rv += struct.pack(">BI", 2, len(sd)) + sd
            else:
                raise NotImplementedError(
                    "Cannot serialize element of type %s" % type(v)
                )
        return rv

    def __prep_message(self, data):
        self.ser += 1
        now = int(time.time())

        d = {}
        d[b"_auth"] = {}
        d[b"_ctrl"] = {}
        d[b"_ctrl"][b"_ser"] = b"%d" % self.ser
        d[b"_ctrl"][b"_tim"] = b"%d" % now
        d[b"_ctrl"][b"_exp"] = b"%d" % (now + 60)
        if self.nonce is not None:
            d[b"_ctrl"][b"_nonce"] = self.nonce
        d[b"_data"] = data

        msg = self.__serialize_dict(d, ignore_auth=True)
        hash = hmac.new(self.secret, msg, self.hlalgo).digest()
        bhash = base64.b64encode(hash)
        if self.algo == "md5":
            d[b"_auth"][b"hmd5"] = struct.pack("22s", bhash)
        else:
            d[b"_auth"][b"hsha"] = struct.pack("B88s", self.__algos[self.algo], bhash)
        msg = self.__serialize_dict(d)
        msg = struct.pack(">II", len(msg) + 4, 1) + msg
        return msg

    def __verify_msg(self, msg):
        if self.nonce is not None and msg[b"_ctrl"][b"_nonce"] != self.nonce:
            return False
        bhash = msg[b"_auth"][b"hmd5" if self.algo == "md5" else b"hsha"]
        bhash += b"=" * (4 - (len(bhash) % 4))
        remote_hash = base64.b64decode(bhash)
        my_msg = self.__serialize_dict(msg, ignore_auth=True)
        my_hash = hmac.new(self.secret, my_msg, self.hlalgo).digest()
        return my_hash == remote_hash

    def __command(self, data):
        msg = self.__prep_message(data)
        sent = self.socket.send(msg)
        if sent != len(msg):
            raise IOError("Cannot send the message")

        header = self.socket.recv(8)
        if len(header) != 8:
            # What should we throw here? Bad auth can cause this...
            raise IOError("Can't read response header")

        length, version = struct.unpack(">II", header)
        if version != 1:
            raise NotImplementedError("Wrong message version %d" % version)

        # it includes the header
        length -= 4
        data = self.socket.recv(length, socket.MSG_WAITALL)
        if len(data) != length:
            raise IOError("Can't read response data")

        msg = self.__parse_message(data)
        if not self.__verify_msg(msg):
            raise IOError("Authentication failure")

        return msg

    def __connect_login(self):
        self.socket = socket.create_connection(self.host)
        self.nonce = None
        msg = self.__command({b"type": b"null"})
        self.nonce = msg[b"_ctrl"][b"_nonce"]

    def __parse_element(self, input):
        pos = 0
        labellen = input[pos]
        pos += 1
        label = input[pos : pos + labellen]
        pos += labellen
        type = input[pos]
        pos += 1
        datalen = struct.unpack(">I", input[pos : pos + 4])[0]
        pos += 4
        data = input[pos : pos + datalen]
        pos += datalen
        rest = input[pos:]

        if type == 1:  # raw binary value
            return label, data, rest
        elif type == 2:  # dictionary
            d = {}
            while len(data) > 0:
                ilabel, value, data = self.__parse_element(data)
                d[ilabel] = value
            return label, d, rest
        # TODO type 3 - list
        else:
            raise NotImplementedError("Unknown element type %d" % type)

    def __parse_message(self, input):
        rv = {}
        while len(input) > 0:
            label, value, input = self.__parse_element(input)
            rv[label] = value
        return rv
