#!/usr/bin/python
############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

import dns
import dns.edns
import struct


class Protoss(dns.edns.Option):
    OPTION_CODE = 0x4F44
    MAGIC_BITS = 0x4F444E53
    VERSION = 1
    FLAG_NONE = 0x00
    FLAG_FALSIFY = 0x01
    FLAG_NOECS = 0x02

    KEYS = {
        "va": {
            "type": 0x04,
            "struct": "I"
        },
        "org": {
            "type": 0x08,
            "struct": "L"
        },
        "ip4": {
            "type": 0x10,
            "struct": "L"
        },
        "ip6": {
            "type": 0x20,
            "struct": "QQ",
            "formater": lambda x: (x >> 64, x & (2 ** 32 - 1))
        },
        "device": {
            "type": 0x40,
            "struct": "Q"
        }
    }

    def __init__(self, flags=0, **kwargs):
        super(Protoss, self).__init__(Protoss.OPTION_CODE)
        self.options = kwargs
        self.flags = flags
        for key in kwargs.keys():
            if key not in Protoss.KEYS.keys():
                raise Exception("%s is not a valid option" % key)

    def pack_value(self, option, value):
        opt_data = Protoss.KEYS[option]
        fmt = "!H%s" % opt_data["struct"]

        if "formater" in opt_data:
            value = opt_data["formater"](value)
        else:
            value = (value,)
        return struct.pack(fmt, opt_data["type"], *value)

    def to_wire(self, file):
        header = struct.pack('!LBB', Protoss.MAGIC_BITS,
                             Protoss.VERSION, self.flags)
        file.write(header)
        for key, value in self.options.iteritems():
            print key, value
            file.write(self.pack_value(key, value))

    @classmethod
    def from_wire(cls, option, wire, current, olen):
        pass


dns.edns._type_to_class[Protoss.OPTION_CODE] = Protoss

if __name__ == "__main__":
    import dns.message
    import dns.query
    import socket

    # Convert IP address strings to numbers
    ipv4 = struct.unpack("!L", socket.inet_pton(socket.AF_INET, '10.0.0.4'))[0]
    hi, lo = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, 'fe0f::1'))
    ipv6 = (hi << 64) | lo

    # Include organization ID and IPv4 address in Protoss packet.
    P = Protoss(org=1816793, ip4=ipv4)
    message = dns.message.make_query("a.example", "A")
    message.use_edns(options=[P])
    r = dns.query.udp(message, "10.53.0.2", port=5300)
    print r

    # Generate a Protoss packet containing the same information as the two
    # above options.  Basically just put the Device ID in the
    # Protoss packet too.  This keeps some firewalls from dropping the packet.
    P = Protoss(org=1816793, ip4=ipv4, device=0xdeadbeef)
    message = dns.message.make_query("a.example", "A")
    message.use_edns(options=[P])
    r = dns.query.udp(message, "10.53.0.2", port=5300, timeout=10)
    print r

    # Same as above but with an IPv6 client address instead of IPv4.
    P = Protoss(org=1816793, ip6=ipv6, device=0xdeadbeef)
    message = dns.message.make_query("a.example", "A")
    message.use_edns(options=[P])
    r = dns.query.udp(message, "10.53.0.2", port=5300, timeout=10)
    print r

    # Generate a packet with Protoss EDNS0 options
    # Include organization ID, Virtual Appliance ID and IPv4 address.  This
    # would allow OpenDNS to apply filtering to the internal IP addres.
    P = Protoss(org=1816793, va=30280231, ip4=ipv4)
    message = dns.message.make_query("a.example", "A")
    message.use_edns(options=[P])
    r = dns.query.udp(message, "10.53.0.2", port=5300, timeout=10)
    print r
