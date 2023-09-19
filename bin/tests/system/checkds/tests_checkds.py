#!/usr/bin/python3

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

import mmap
import os
import subprocess
import sys
import time

import pytest

pytest.importorskip("dns", minversion="2.0.0")
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver


pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 7), reason="Python >= 3.7 required [GL #3001]"
)


def has_signed_apex_nsec(zone, response):
    has_nsec = False
    has_rrsig = False

    ttl = 300
    nextname = "a."
    labelcount = zone.count(".")  # zone is specified as FQDN
    types = "NS SOA RRSIG NSEC DNSKEY"
    match = "{0} {1} IN NSEC {2}{0} {3}".format(zone, ttl, nextname, types)
    sig = "{0} {1} IN RRSIG NSEC 13 {2} 300".format(zone, ttl, labelcount)

    for rr in response.answer:
        if match in rr.to_text():
            has_nsec = True
        if sig in rr.to_text():
            has_rrsig = True

    if not has_nsec:
        print("error: missing apex NSEC record in response")
    if not has_rrsig:
        print("error: missing NSEC signature in response")

    return has_nsec and has_rrsig


def do_query(server, qname, qtype, tcp=False):
    query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True)
    try:
        if tcp:
            response = dns.query.tcp(
                query, server.nameservers[0], timeout=3, port=server.port
            )
        else:
            response = dns.query.udp(
                query, server.nameservers[0], timeout=3, port=server.port
            )
    except dns.exception.Timeout:
        print(
            "error: query timeout for query {} {} to {}".format(
                qname, qtype, server.nameservers[0]
            )
        )
        return None

    return response


def verify_zone(zone, transfer):
    verify = os.getenv("VERIFY")
    assert verify is not None

    filename = "{}out".format(zone)
    with open(filename, "w", encoding="utf-8") as file:
        for rr in transfer.answer:
            file.write(rr.to_text())
            file.write("\n")

    # dnssec-verify command with default arguments.
    verify_cmd = [verify, "-z", "-o", zone, filename]

    verifier = subprocess.run(verify_cmd, capture_output=True, check=True)

    if verifier.returncode != 0:
        print("error: dnssec-verify {} failed".format(zone))
        sys.stderr.buffer.write(verifier.stderr)

    return verifier.returncode == 0


def read_statefile(server, zone):
    addr = server.nameservers[0]
    count = 0
    keyid = 0
    state = {}

    response = do_query(server, zone, "DS", tcp=True)
    if not isinstance(response, dns.message.Message):
        print("error: no response for {} DS from {}".format(zone, addr))
        return {}

    if response.rcode() == dns.rcode.NOERROR:
        # fetch key id from response.
        for rr in response.answer:
            if rr.match(
                dns.name.from_text(zone),
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                dns.rdatatype.NONE,
            ):
                if count == 0:
                    keyid = list(dict(rr.items).items())[0][0].key_tag
                count += 1

        if count != 1:
            print(
                "error: expected a single DS in response for {} from {},"
                "got {}".format(zone, addr, count)
            )
            return {}
    else:
        print(
            "error: {} response for {} DNSKEY from {}".format(
                dns.rcode.to_text(response.rcode()), zone, addr
            )
        )
        return {}

    filename = "ns9/K{}+013+{:05d}.state".format(zone, keyid)
    print("read state file {}".format(filename))

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                if line.startswith(";"):
                    continue
                key, val = line.strip().split(":", 1)
                state[key.strip()] = val.strip()

    except FileNotFoundError:
        # file may not be written just yet.
        return {}

    return state


def zone_check(server, zone):
    addr = server.nameservers[0]
    fqdn = "{}.".format(zone)

    # wait until zone is fully signed.
    signed = False
    for _ in range(10):
        response = do_query(server, fqdn, "NSEC")
        if not isinstance(response, dns.message.Message):
            print("error: no response for {} NSEC from {}".format(fqdn, addr))
        elif response.rcode() == dns.rcode.NOERROR:
            signed = has_signed_apex_nsec(fqdn, response)
        else:
            print(
                "error: {} response for {} NSEC from {}".format(
                    dns.rcode.to_text(response.rcode()), fqdn, addr
                )
            )

        if signed:
            break

        time.sleep(1)

    assert signed

    # check if zone if DNSSEC valid.
    verified = False
    transfer = do_query(server, fqdn, "AXFR", tcp=True)
    if not isinstance(transfer, dns.message.Message):
        print("error: no response for {} AXFR from {}".format(fqdn, addr))
    elif transfer.rcode() == dns.rcode.NOERROR:
        verified = verify_zone(fqdn, transfer)
    else:
        print(
            "error: {} response for {} AXFR from {}".format(
                dns.rcode.to_text(transfer.rcode()), fqdn, addr
            )
        )

    assert verified


def keystate_check(server, zone, key):
    fqdn = "{}.".format(zone)
    val = 0
    deny = False

    search = key
    if key.startswith("!"):
        deny = True
        search = key[1:]

    for _ in range(10):
        state = read_statefile(server, fqdn)
        try:
            val = state[search]
        except KeyError:
            pass

        if not deny and val != 0:
            break
        if deny and val == 0:
            break

        time.sleep(1)

    if deny:
        assert val == 0
    else:
        assert val != 0


def rekey(zone):
    rndc = os.getenv("RNDC")
    assert rndc is not None

    port = os.getenv("CONTROLPORT")
    assert port is not None

    # rndc loadkeys.
    rndc_cmd = [
        rndc,
        "-c",
        "../_common/rndc.conf",
        "-p",
        port,
        "-s",
        "10.53.0.9",
        "loadkeys",
        zone,
    ]
    controller = subprocess.run(rndc_cmd, capture_output=True, check=True)

    if controller.returncode != 0:
        print("error: rndc loadkeys {} failed".format(zone))
        sys.stderr.buffer.write(controller.stderr)

    assert controller.returncode == 0


def wait_for_log(filename, zone, log):
    found = False

    for _ in range(10):
        print("read log file {}".format(filename))

        try:
            with open(filename, "r", encoding="utf-8") as file:
                s = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
                if s.find(bytes(log, "ascii")) != -1:
                    found = True
        except FileNotFoundError:
            print("file not found {}".format(filename))

        if found:
            break

        print("rekey")
        rekey(zone)

        print("sleep")
        time.sleep(1)

    assert found


def checkds_dspublished(named_port, checkds, addr):
    # We create resolver instances that will be used to send queries.
    server = dns.resolver.Resolver()
    server.nameservers = ["10.53.0.9"]
    server.port = named_port

    parent = dns.resolver.Resolver()
    parent.nameservers = ["10.53.0.2"]
    parent.port = named_port

    #
    # 1.1.1: DS is correctly published in parent.
    # parental-agents: ns2
    #

    # The simple case.
    zone = "good.{}.dspublish.ns2".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from {}".format(zone, addr),
    )
    keystate_check(parent, zone, "DSPublish")

    #
    # 1.1.2: DS is not published in parent.
    # parental-agents: ns5
    #
    zone = "not-yet.{}.dspublish.ns5".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from 10.53.0.5".format(zone),
    )
    keystate_check(parent, zone, "!DSPublish")

    #
    # 1.1.3: The parental agent is badly configured.
    # parental-agents: ns6
    #
    zone = "bad.{}.dspublish.ns6".format(checkds)
    zone_check(server, zone)
    if checkds == "explicit":
        wait_for_log(
            "ns9/named.run",
            zone,
            "zone {}/IN (signed): checkds: bad DS response from 10.53.0.6".format(zone),
        )
    elif checkds == "yes":
        wait_for_log(
            "ns9/named.run",
            zone,
            "zone {}/IN (signed): checkds: error during parental-agents processing".format(
                zone
            ),
        )
    keystate_check(parent, zone, "!DSPublish")

    #
    # 1.1.4: DS is published, but has bogus signature.
    #
    # TBD

    #
    # 1.2.1: DS is correctly published in all parents.
    # parental-agents: ns2, ns4
    #
    zone = "good.{}.dspublish.ns2-4".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from {}".format(zone, addr),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.4".format(zone),
    )
    keystate_check(parent, zone, "DSPublish")

    #
    # 1.2.2: DS is not published in some parents.
    # parental-agents: ns2, ns4, ns5
    #
    zone = "incomplete.{}.dspublish.ns2-4-5".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from {}".format(zone, addr),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.4".format(zone),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from 10.53.0.5".format(zone),
    )
    keystate_check(parent, zone, "!DSPublish")

    #
    # 1.2.3: One parental agent is badly configured.
    # parental-agents: ns2, ns4, ns6
    #
    zone = "bad.{}.dspublish.ns2-4-6".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from {}".format(zone, addr),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.4".format(zone),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: bad DS response from 10.53.0.6".format(zone),
    )
    keystate_check(parent, zone, "!DSPublish")

    #
    # 1.2.4: DS is completely published, bogus signature.
    #
    # TBD

    # TBD: Check with TSIG
    # TBD: Check with TLS


def checkds_dswithdrawn(named_port, checkds, addr):
    # We create resolver instances that will be used to send queries.
    server = dns.resolver.Resolver()
    server.nameservers = ["10.53.0.9"]
    server.port = named_port

    parent = dns.resolver.Resolver()
    parent.nameservers = ["10.53.0.2"]
    parent.port = named_port

    #
    # 2.1.1: DS correctly withdrawn from the parent.
    # parental-agents: ns5
    #

    # The simple case.
    zone = "good.{}.dsremoved.ns5".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from {}".format(zone, addr),
    )
    keystate_check(parent, zone, "DSRemoved")

    #
    # 2.1.2: DS is published in the parent.
    # parental-agents: ns2
    #
    zone = "still-there.{}.dsremoved.ns2".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.2".format(zone),
    )
    keystate_check(parent, zone, "!DSRemoved")

    #
    # 2.1.3: The parental agent is badly configured.
    # parental-agents: ns6
    #
    zone = "bad.{}.dsremoved.ns6".format(checkds)
    zone_check(server, zone)
    if checkds == "explicit":
        wait_for_log(
            "ns9/named.run",
            zone,
            "zone {}/IN (signed): checkds: bad DS response from 10.53.0.6".format(zone),
        )
    elif checkds == "yes":
        wait_for_log(
            "ns9/named.run",
            zone,
            "zone {}/IN (signed): checkds: error during parental-agents processing".format(
                zone
            ),
        )
    keystate_check(parent, zone, "!DSRemoved")

    #
    # 2.1.4: DS is withdrawn, but has bogus signature.
    #
    # TBD

    #
    # 2.2.1: DS is correctly withdrawn from all parents.
    # parental-agents: ns5, ns7
    #
    zone = "good.{}.dsremoved.ns5-7".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from {}".format(zone, addr),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from 10.53.0.7".format(zone),
    )
    keystate_check(parent, zone, "DSRemoved")

    #
    # 2.2.2: DS is not withdrawn from some parents.
    # parental-agents: ns2, ns5, ns7
    #
    zone = "incomplete.{}.dsremoved.ns2-5-7".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.2".format(zone),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from {}".format(zone, addr),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from 10.53.0.7".format(zone),
    )
    keystate_check(parent, zone, "!DSRemoved")

    #
    # 2.2.3: One parental agent is badly configured.
    # parental-agents: ns5, ns6, ns7
    #
    zone = "bad.{}.dsremoved.ns5-6-7".format(checkds)
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from {}".format(zone, addr),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from 10.53.0.7".format(zone),
    )
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: bad DS response from 10.53.0.6".format(zone),
    )
    keystate_check(parent, zone, "!DSRemoved")

    #
    # 2.2.4:: DS is removed completely, bogus signature.
    #
    # TBD


def test_checkds_reference(named_port):
    # We create resolver instances that will be used to send queries.
    server = dns.resolver.Resolver()
    server.nameservers = ["10.53.0.9"]
    server.port = named_port

    parent = dns.resolver.Resolver()
    parent.nameservers = ["10.53.0.2"]
    parent.port = named_port

    # Using a reference to parental-agents.
    zone = "reference.explicit.dspublish.ns2"
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.8".format(zone),
    )
    keystate_check(parent, zone, "DSPublish")


def test_checkds_resolver(named_port):
    # We create resolver instances that will be used to send queries.
    server = dns.resolver.Resolver()
    server.nameservers = ["10.53.0.9"]
    server.port = named_port

    parent = dns.resolver.Resolver()
    parent.nameservers = ["10.53.0.2"]
    parent.port = named_port

    # Using a resolver as parental-agent (ns3).
    zone = "resolver.explicit.dspublish.ns2"
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.3".format(zone),
    )
    keystate_check(parent, zone, "DSPublish")

    # Using a resolver as parental-agent (ns3).
    zone = "resolver.explicit.dsremoved.ns5"
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: empty DS response from 10.53.0.3".format(zone),
    )
    keystate_check(parent, zone, "DSRemoved")


def test_checkds_no_ent(named_port):
    # We create resolver instances that will be used to send queries.
    server = dns.resolver.Resolver()
    server.nameservers = ["10.53.0.9"]
    server.port = named_port

    parent = dns.resolver.Resolver()
    parent.nameservers = ["10.53.0.2"]
    parent.port = named_port

    zone = "no-ent.ns2"
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.2".format(zone),
    )
    keystate_check(parent, zone, "DSPublish")

    zone = "no-ent.ns5"
    zone_check(server, zone)
    wait_for_log(
        "ns9/named.run",
        zone,
        "zone {}/IN (signed): checkds: DS response from 10.53.0.5".format(zone),
    )
    keystate_check(parent, zone, "DSRemoved")


def test_checkds_dspublished(named_port):
    checkds_dspublished(named_port, "explicit", "10.53.0.8")
    checkds_dspublished(named_port, "yes", "10.53.0.2")


def test_checkds_dswithdrawn(named_port):
    checkds_dswithdrawn(named_port, "explicit", "10.53.0.10")
    checkds_dswithdrawn(named_port, "yes", "10.53.0.5")


def test_checkds_no(named_port):
    # We create resolver instances that will be used to send queries.
    server = dns.resolver.Resolver()
    server.nameservers = ["10.53.0.9"]
    server.port = named_port

    parent = dns.resolver.Resolver()
    parent.nameservers = ["10.53.0.2"]
    parent.port = named_port

    zone_check(server, "good.no.dspublish.ns2")
    keystate_check(parent, "good.no.dspublish.ns2", "!DSPublish")

    zone_check(server, "good.no.dspublish.ns2-4")
    keystate_check(parent, "good.no.dspublish.ns2-4", "!DSPublish")

    zone_check(server, "good.no.dsremoved.ns5")
    keystate_check(parent, "good.no.dsremoved.ns5", "!DSRemoved")

    zone_check(server, "good.no.dsremoved.ns5-7")
    keystate_check(parent, "good.no.dsremoved.ns5-7", "!DSRemoved")
