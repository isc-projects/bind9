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

from __future__ import print_function
import os
import sys
import signal
import socket
import select
import struct

import dns, dns.message
from dns.rcode import *

def create_response(msg):
    m = dns.message.from_wire(msg)
    qname = m.question[0].name.to_text()
    rrtype = m.question[0].rdtype
    typename = dns.rdatatype.to_text(rrtype)

    with open("query.log", "a") as f:
        f.write("%s %s\n" % (typename, qname))
        print("%s %s" % (typename, qname), end=" ")

    r = dns.message.make_response(m)
    r.set_rcode(SERVFAIL)
    return r

def sigterm(signum, frame):
    print("Shutting down now...")
    os.remove("ans.pid")
    running = False
    sys.exit(0)

ip4 = "10.53.0.8"

try: port=int(os.environ["PORT"])
except: port=5300

query4_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
query4_udp.bind((ip4, port))

query4_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
query4_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
query4_tcp.bind((ip4, port))
query4_tcp.listen(100)

signal.signal(signal.SIGTERM, sigterm)

f = open("ans.pid", "w")
pid = os.getpid()
print (pid, file=f)
f.close()

running = True

print ("Listening on %s port %d" % (ip4, port))
print ("Ctrl-c to quit")

input = [query4_udp, query4_tcp]

n_udp = 0
n_tcp = 0
hung_conns = []

while running:
    try:
        inputready, outputready, exceptready = select.select(input, [], [])
    except select.error as e:
        break
    except socket.error as e:
        break
    except KeyboardInterrupt:
        break

    for s in inputready:
        if s == query4_udp:
            print("UDP query received on %s" % ip4, end=" ")
            n_udp = n_udp + 1
            msg = s.recvfrom(65535)
            # Do not response to every other query.
            if n_udp % 2 == 1:
                print("NO RESPONSE")
                continue
            rsp = create_response(msg[0])
            if rsp:
                print(dns.rcode.to_text(rsp.rcode()))
                s.sendto(rsp.to_wire(), msg[1])
            else:
                print("NO RESPONSE")
        elif s == query4_tcp:
            print("TCP query received on %s" % ip4, end=" ")
            n_tcp = n_tcp + 1
            conn = None
            try:
                conn, addr = s.accept()
                # Do not response to every other query, hang the connection.
                if n_tcp % 2 == 1:
                    print("NO RESPONSE")
                    hung_conns.append(conn)
                    conn = None
                    continue
                else:
                    # get TCP message length
                    msg = conn.recv(2)
                    if len(msg) != 2:
                        print("NO RESPONSE")
                        conn.close()
                        continue
                    length = struct.unpack('>H', msg[:2])[0]
                    msg = conn.recv(length)
                    if len(msg) != length:
                        print("NO RESPONSE")
                        conn.close()
                        continue
                    rsp = create_response(msg)
                    if rsp:
                        print(dns.rcode.to_text(rsp.rcode()))
                        wire = rsp.to_wire()
                        conn.send(struct.pack('>H', len(wire)))
                        conn.send(wire)
                    else:
                        print("NO RESPONSE")
            except:
                print("NO RESPONSE")
            if conn:
                conn.close()

    if not running:
        break
