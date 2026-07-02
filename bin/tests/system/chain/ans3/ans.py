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

############################################################################
# ans.py: See README.anspy for details.
############################################################################

from __future__ import print_function
import os
import sys
import signal
import socket
import select

import dns
import dns.message
import dns.query
from dns.rdatatype import *
from dns.rdataclass import *
from dns.rcode import *
from dns.name import *


############################################################################
# Respond to a DNS query.
############################################################################
def create_response(msg):
    ttl = 60
    zone = "example.broken."
    nsname = f"ns3.{zone}"
    synth = f"synth-then-dname.{zone}"
    synth2 = f"synth2-then-dname.{zone}"

    m = dns.message.from_wire(msg)
    qname = m.question[0].name.to_text()

    # prepare the response and convert to wire format
    r = dns.message.make_response(m)

    # get qtype
    rrtype = m.question[0].rdtype
    qtype = dns.rdatatype.to_text(rrtype)
    print(f"request: {qname}/{qtype}")

    rcode = "NOERROR"
    if qname == zone:
        if qtype == "SOA":
            r.answer.append(dns.rrset.from_text(qname, ttl, IN, SOA, ". . 0 0 0 0 0"))
        elif qtype == "NS":
            r.answer.append(dns.rrset.from_text(qname, ttl, IN, NS, nsname))
            r.additional.append(dns.rrset.from_text(nsname, ttl, IN, A, ip4))
    elif qname == f"cname-to-{synth2}":
        r.answer.append(dns.rrset.from_text(qname, ttl, IN, CNAME, f"name.{synth2}"))
        r.answer.append(dns.rrset.from_text(f"name.{synth2}", ttl, IN, CNAME, "name."))
        r.answer.append(dns.rrset.from_text(synth2, ttl, IN, DNAME, "."))
    elif qname == f"{synth}" or qname == f"{synth2}":
        if qtype == "DNAME":
            r.answer.append(dns.rrset.from_text(qname, ttl, IN, DNAME, "."))
    elif qname == f"name.{synth}":
        r.answer.append(dns.rrset.from_text(qname, ttl, IN, CNAME, "name."))
        r.answer.append(dns.rrset.from_text(synth, ttl, IN, DNAME, "."))
    elif qname == f"name.{synth2}":
        r.answer.append(dns.rrset.from_text(qname, ttl, IN, CNAME, "name."))
        r.answer.append(dns.rrset.from_text(synth2, ttl, IN, DNAME, "."))
    elif qname == "ns3.example.dname.":
        # This and the next two code branches referring to the "example.dname"
        # zone are necessary for the resolver variant of the CVE-2021-25215
        # regression test to work.  A named instance cannot be used for
        # serving the DNAME records below as a version of BIND vulnerable to
        # CVE-2021-25215 would crash while answering the queries asked by
        # the tested resolver.
        if qtype == "A":
            r.answer.append(dns.rrset.from_text(qname, ttl, IN, A, ip4))
        elif qtype == "AAAA":
            r.authority.append(
                dns.rrset.from_text("example.dname.", ttl, IN, SOA, ". . 0 0 0 0 0")
            )
    elif qname == "self.example.self..example.dname.":
        r.answer.append(
            dns.rrset.from_text("self.example.dname.", ttl, IN, DNAME, "dname.")
        )
        r.answer.append(
            dns.rrset.from_text(qname, ttl, IN, CNAME, "self.example.dname.")
        )
    elif qname == "self.example.dname.":
        if qtype == "DNAME":
            r.answer.append(dns.rrset.from_text(qname, ttl, IN, DNAME, "dname."))
    else:
        rcode = "REFUSED"

    r.flags |= dns.flags.AA
    r.use_edns()
    return r.to_wire()


def sigterm(signum, frame):
    print("Shutting down now...")
    os.remove("ans.pid")
    running = False
    sys.exit(0)


############################################################################
# Main
#
# Set up responder and control channel, open the pid file, and start
# the main loop, listening for queries on the query channel or commands
# on the control channel and acting on them.
############################################################################
ip4 = "10.53.0.3"
ip6 = "fd92:7065:b8e:ffff::3"

try:
    port = int(os.environ["PORT"])
except:
    port = 5300

query4_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
query4_udp.bind((ip4, port))

query4_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
query4_tcp.bind((ip4, port))
query4_tcp.listen(1)
query4_tcp.settimeout(1)

havev6 = True
try:
    query6_udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        query6_udp.bind((ip6, port))
    except:
        query6_udp.close()
        havev6 = False

    query6_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        query6_tcp.bind((ip4, port))
        query6_tcp.listen(1)
        query6_tcp.settimeout(1)
    except:
        query6_tcp.close()
        havev6 = False
except:
    havev6 = False

signal.signal(signal.SIGTERM, sigterm)

f = open("ans.pid", "w")
pid = os.getpid()
print(pid, file=f)
f.close()

running = True

print("Listening on %s port %d" % (ip4, port))
if havev6:
    print("Listening on %s port %d" % (ip6, port))
print("Ctrl-c to quit")

if havev6:
    input = [query4_udp, query4_tcp, query6_udp, query6_tcp]
else:
    input = [query4_udp, query4_tcp]

while running:
    try:
        inputready, outputready, exceptready = select.select(input, [], [])
    except select.error:
        break
    except socket.error:
        break
    except KeyboardInterrupt:
        break

    for s in inputready:
        if s == query4_udp or s == query6_udp:
            print("Query received on %s" % (ip4 if s == query4_udp else ip6))
            # Handle incoming queries
            msg = s.recvfrom(65535)
            rsp = create_response(msg[0])
            if rsp:
                s.sendto(rsp, msg[1])
        elif s == query4_tcp or s == query6_tcp:
            try:
                conn, _ = s.accept()
                if s == query4_tcp or s == query6_tcp:
                    print(
                        "TCP Query received on %s" % (ip4 if s == query4_tcp else ip6),
                        end=" ",
                    )
                # get TCP message length
                msg = conn.recv(2)
                if len(msg) != 2:
                    print("couldn't read TCP message length")
                    continue
                length = struct.unpack(">H", msg[:2])[0]
                msg = conn.recv(length)
                if len(msg) != length:
                    print("couldn't read TCP message")
                    continue
                rsp = create_response(msg)
                if rsp:
                    conn.send(struct.pack(">H", len(rsp)))
                    conn.send(rsp)
                conn.close()
            except socket.error as e:
                print("error: %s" % str(e))
    if not running:
        break
