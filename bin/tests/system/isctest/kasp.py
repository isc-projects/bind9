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

import os
import time

from datetime import datetime
from datetime import timedelta

import dns
import isctest.log


DEFAULT_TTL = 300


def _save_response(response, fname):
    with open(fname, "w", encoding="utf-8") as file:
        file.write(response.to_text())


def _query(server, qname, qtype, outfile=None):
    query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True)
    try:
        response = dns.query.tcp(query, server.ip, port=server.ports.dns, timeout=3)
    except dns.exception.Timeout:
        isctest.log.debug(f"query timeout for query {qname} {qtype} to {server.ip}")
        return None

    if outfile is not None:
        _save_response(response, outfile)

    return response


def addtime(value, plus):
    # Get timing metadata from a value plus additional time.
    # Convert "%Y%m%d%H%M%S" format to epoch seconds.
    # Then, add the additional time (can be negative).
    now = datetime.strptime(value, "%Y%m%d%H%M%S")
    delta = timedelta(seconds=plus)
    then = now + delta
    return then.strftime("%Y%m%d%H%M%S")


def get_timing_metadata(key, metadata, keydir=None, offset=0, must_exist=True):
    value = "0"

    if keydir is not None:
        keyfile = "{}/{}.key".format(keydir, key)
    else:
        keyfile = "{}.key".format(key)

    with open(keyfile, "r", encoding="utf-8") as file:
        for line in file:
            if "; {}".format(metadata) in line:
                value = line.split()[2]
                break

    if must_exist:
        assert int(value) > 0

    if int(value) > 0:
        return addtime(value, offset)

    return "0"


def get_metadata(key, metadata, keydir=None, must_exist=True):
    if keydir is not None:
        statefile = "{}/{}.state".format(keydir, key)
    else:
        statefile = "{}.state".format(key)

    value = "undefined"
    with open(statefile, "r", encoding="utf-8") as file:
        for line in file:
            if f"{metadata}: " in line:
                value = line.split()[1]
                break

    if must_exist:
        assert value != "undefined"

    return value


def get_keystate(key, metadata, keydir=None, must_exist=True):

    return get_metadata(key, metadata, keydir, must_exist)


def get_keytag(key):
    return int(key[-5:])


def get_keyrole(key, keydir=None):
    ksk = "no"
    zsk = "no"

    if keydir is not None:
        statefile = "{}/{}.state".format(keydir, key)
    else:
        statefile = "{}.state".format(key)

    with open(statefile, "r", encoding="utf-8") as file:
        for line in file:
            if "KSK: " in line:
                ksk = line.split()[1]
            if "ZSK: " in line:
                zsk = line.split()[1]

    return ksk == "yes", zsk == "yes"


def dnskey_equals(key, value, keydir=None, cdnskey=False):
    if keydir is not None:
        keyfile = f"{keydir}/{key}.key"
    else:
        keyfile = f"{key}.key"

    dnskey = value.split()

    if cdnskey:
        # fourth element is the rrtype
        assert dnskey[3] == "CDNSKEY"
        dnskey[3] = "DNSKEY"

    dnskey_fromfile = []
    rdata = " ".join(dnskey[:7])

    with open(keyfile, "r", encoding="utf-8") as file:
        for line in file:
            if f"{rdata}" in line:
                dnskey_fromfile = line.split()

    pubkey_fromfile = "".join(dnskey_fromfile[7:])
    pubkey_fromwire = "".join(dnskey[7:])

    return pubkey_fromfile == pubkey_fromwire


def cds_equals(key, value, alg, keydir=None):
    if keydir is not None:
        keyfile = f"{keydir}/{key}.key"
    else:
        keyfile = f"{key}.key"

    cds = value.split()

    dsfromkey_command = [
        *os.environ.get("DSFROMKEY").split(),
        "-T",
        "3600",
        "-a",
        alg,
        "-C",
        "-w",
        keyfile,
    ]

    out = isctest.run.cmd(dsfromkey_command, log_stdout=True)
    dsfromkey = out.stdout.decode("utf-8").split()
    index = 6
    while index < len(cds):
        dsfromkey[index] = dsfromkey[index].lower()
        index += 1

    rdata_fromfile = " ".join(dsfromkey[:7])
    rdata_fromwire = " ".join(cds[:7])
    if rdata_fromfile != rdata_fromwire:
        isctest.log.debug(f"CDS RDATA MISMATCH: {rdata_fromfile} - {rdata_fromwire}")
        return False

    digest_fromfile = "".join(cds[7:])
    digest_fromwire = "".join(cds[7:])
    if digest_fromfile != digest_fromwire:
        isctest.log.debug(f"CDS DIGEST MISMATCH: {digest_fromfile} - {digest_fromwire}")
        return False

    return digest_fromfile == digest_fromwire


def zone_is_signed(server, zone):
    addr = server.ip
    fqdn = f"{zone}."

    # wait until zone is fully signed
    signed = False
    for _ in range(10):
        response = _query(server, fqdn, dns.rdatatype.NSEC)
        if not isinstance(response, dns.message.Message):
            isctest.log.debug(f"no response for {fqdn} NSEC from {addr}")
        elif response.rcode() != dns.rcode.NOERROR:
            rcode = dns.rcode.to_text(response.rcode())
            isctest.log.debug(f"{rcode} response for {fqdn} NSEC from {addr}")
        else:
            has_nsec = False
            has_rrsig = False
            for rr in response.answer:
                if not has_nsec:
                    has_nsec = rr.match(
                        dns.name.from_text(fqdn),
                        dns.rdataclass.IN,
                        dns.rdatatype.NSEC,
                        dns.rdatatype.NONE,
                    )
                if not has_rrsig:
                    has_rrsig = rr.match(
                        dns.name.from_text(fqdn),
                        dns.rdataclass.IN,
                        dns.rdatatype.RRSIG,
                        dns.rdatatype.NSEC,
                    )

            if not has_nsec:
                isctest.log.debug(
                    f"missing apex {fqdn} NSEC record in response from {addr}"
                )
            if not has_rrsig:
                isctest.log.debug(
                    f"missing {fqdn} NSEC signature in response from {addr}"
                )

            signed = has_nsec and has_rrsig

        if signed:
            break

        time.sleep(1)

    assert signed


def dnssec_verify(server, zone):
    # Check if zone if DNSSEC valid with dnssec-verify.
    fqdn = f"{zone}."
    transfer = _query(server, fqdn, dns.rdatatype.AXFR)
    if not isinstance(transfer, dns.message.Message):
        isctest.log.debug(f"no response for {fqdn} AXFR from {server.ip}")
    elif transfer.rcode() != dns.rcode.NOERROR:
        rcode = dns.rcode.to_text(transfer.rcode())
        isctest.log.debug(f"{rcode} response for {fqdn} AXFR from {server.ip}")
    else:
        zonefile = f"{zone}.axfr"
        with open(zonefile, "w", encoding="utf-8") as file:
            for rr in transfer.answer:
                file.write(rr.to_text())
                file.write("\n")

    verify_command = [*os.environ.get("VERIFY").split(), "-z", "-o", zone, zonefile]

    isctest.run.cmd(verify_command)


def check_dnssecstatus(server, zone, keys, policy=None, view=None):
    # Call rndc dnssec -status on 'server' for 'zone'. Expect 'policy' in
    # the output. This is a loose verification, it just tests if the right
    # policy name is returned, and if all expected keys are listed.
    response = ""
    if view is None:
        response = server.rndc("dnssec -status {}".format(zone), log=False)
    else:
        response = server.rndc("dnssec -status {} in {}".format(zone, view), log=False)

    if policy is None:
        assert "Zone does not have dnssec-policy" in response
        return

    assert "dnssec-policy: {}".format(policy) in response

    for key in keys:
        keytag = get_keytag(key)
        assert "key: {}".format(keytag) in response


# pylint: disable=too-many-locals,too-many-branches
def _check_signatures(signatures, covers, fqdn, keys, keydir=None):
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    numsigs = 0
    zrrsig = True
    if covers in [dns.rdatatype.DNSKEY, dns.rdatatype.CDNSKEY, dns.rdatatype.CDS]:
        zrrsig = False
    krrsig = not zrrsig

    for key in keys:
        keytag = get_keytag(key)
        ksk, zsk = get_keyrole(key, keydir=keydir)
        activate = get_timing_metadata(key, "Activate", keydir=keydir)
        inactive = get_timing_metadata(key, "Inactive", keydir=keydir, must_exist=False)

        active = int(now) >= int(activate)
        retired = int(inactive) != 0 and int(inactive) <= int(now)
        signing = active and not retired

        if not signing:
            for rrsig in signatures:
                assert f"{keytag} {fqdn}" not in rrsig
            continue

        if zrrsig and zsk:
            has_rrsig = False
            for rrsig in signatures:
                if f"{keytag} {fqdn}" in rrsig:
                    has_rrsig = True
                    break
            assert has_rrsig
            numsigs += 1

        if zrrsig and not zsk:
            for rrsig in signatures:
                assert f"{keytag} {fqdn}" not in rrsig

        if krrsig and ksk:
            has_rrsig = False
            for rrsig in signatures:
                if f"{keytag} {fqdn}" in rrsig:
                    has_rrsig = True
                    break
            assert has_rrsig
            numsigs += 1

        if krrsig and not ksk:
            for rrsig in signatures:
                assert f"{keytag} {fqdn}" not in rrsig

    return numsigs


# pylint: disable=too-many-arguments
def check_signatures(rrset, covers, fqdn, ksks, zsks, kskdir=None, zskdir=None):
    # Check if signatures with covering type are signed with the right keys.
    # The right keys are the ones that expect a signature and have the
    # correct role.
    numsigs = 0

    signatures = []
    for rr in rrset:
        for rdata in rr:
            rdclass = dns.rdataclass.to_text(rr.rdclass)
            rdtype = dns.rdatatype.to_text(rr.rdtype)
            rrsig = f"{rr.name} {rr.ttl} {rdclass} {rdtype} {rdata}"
            signatures.append(rrsig)

    numsigs += _check_signatures(signatures, covers, fqdn, ksks, keydir=kskdir)
    numsigs += _check_signatures(signatures, covers, fqdn, zsks, keydir=zskdir)

    assert numsigs == len(signatures)


def _check_dnskeys(dnskeys, keys, keydir=None, cdnskey=False):
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    numkeys = 0

    publish_md = "Publish"
    delete_md = "Delete"
    if cdnskey:
        publish_md = f"Sync{publish_md}"
        delete_md = f"Sync{delete_md}"

    for key in keys:
        publish = get_timing_metadata(key, publish_md, keydir=keydir)
        delete = get_timing_metadata(key, delete_md, keydir=keydir, must_exist=False)
        published = int(now) >= int(publish)
        removed = int(delete) != 0 and int(delete) <= int(now)

        if not published or removed:
            for dnskey in dnskeys:
                assert not dnskey_equals(key, dnskey, keydir=keydir, cdnskey=cdnskey)
            continue

        has_dnskey = False
        for dnskey in dnskeys:
            if dnskey_equals(key, dnskey, keydir=keydir, cdnskey=cdnskey):
                has_dnskey = True
                break

        assert has_dnskey
        numkeys += 1

    return numkeys


# pylint: disable=too-many-arguments
def check_dnskeys(rrset, ksks, zsks, kskdir=None, zskdir=None, cdnskey=False):
    # Check if the correct DNSKEY records are published. If the current time
    # is between the timing metadata 'publish' and 'delete', the key must have
    # a DNSKEY record published. If 'cdnskey' is True, check against CDNSKEY
    # records instead.
    numkeys = 0

    dnskeys = []
    for rr in rrset:
        for rdata in rr:
            rdclass = dns.rdataclass.to_text(rr.rdclass)
            rdtype = dns.rdatatype.to_text(rr.rdtype)
            dnskey = f"{rr.name} {rr.ttl} {rdclass} {rdtype} {rdata}"
            dnskeys.append(dnskey)

    numkeys += _check_dnskeys(dnskeys, ksks, keydir=kskdir, cdnskey=cdnskey)
    if not cdnskey:
        numkeys += _check_dnskeys(dnskeys, zsks, keydir=zskdir)

    assert numkeys == len(dnskeys)


# pylint: disable=too-many-locals
def check_cds(rrset, keys, keydir=None):
    # Check if the correct CDS records are published. If the current time
    # is between the timing metadata 'publish' and 'delete', the key must have
    # a DNSKEY record published. If 'cdnskey' is True, check against CDNSKEY
    # records instead.
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    numcds = 0

    cdss = []
    for rr in rrset:
        for rdata in rr:
            rdclass = dns.rdataclass.to_text(rr.rdclass)
            rdtype = dns.rdatatype.to_text(rr.rdtype)
            cds = f"{rr.name} {rr.ttl} {rdclass} {rdtype} {rdata}"
            cdss.append(cds)

    for key in keys:
        ksk, _ = get_keyrole(key, keydir=keydir)
        assert ksk

        publish = get_timing_metadata(key, "SyncPublish", keydir=keydir)
        delete = get_timing_metadata(key, "SyncDelete", keydir=keydir, must_exist=False)
        published = int(now) >= int(publish)
        removed = int(delete) != 0 and int(delete) <= int(now)
        if not published or removed:
            for cds in cdss:
                assert not cds_equals(key, cds, "SHA-256", keydir=keydir)
            continue

        has_cds = False
        for cds in cdss:
            if cds_equals(key, cds, "SHA-256", keydir=keydir):
                has_cds = True
                break

        assert has_cds
        numcds += 1

    assert numcds == len(cdss)


def _query_rrset(server, fqdn, qtype):
    response = _query(server, fqdn, qtype)
    assert response.rcode() == dns.rcode.NOERROR

    rrs = []
    rrsigs = []
    for rrset in response.answer:
        if rrset.match(
            dns.name.from_text(fqdn), dns.rdataclass.IN, dns.rdatatype.RRSIG, qtype
        ):
            rrsigs.append(rrset)
        elif rrset.match(
            dns.name.from_text(fqdn), dns.rdataclass.IN, qtype, dns.rdatatype.NONE
        ):
            rrs.append(rrset)
        else:
            assert False

    return rrs, rrsigs


# pylint: disable=too-many-arguments
def check_apex(server, zone, ksks, zsks, kskdir=None, zskdir=None):
    # Test the apex of a zone. This checks that the SOA and DNSKEY RRsets
    # are signed correctly and with the appropriate keys.
    fqdn = f"{zone}."

    # test dnskey query
    dnskeys, rrsigs = _query_rrset(server, fqdn, dns.rdatatype.DNSKEY)
    assert len(dnskeys) > 0
    check_dnskeys(dnskeys, ksks, zsks, kskdir=kskdir, zskdir=zskdir)
    assert len(rrsigs) > 0
    check_signatures(
        rrsigs, dns.rdatatype.DNSKEY, fqdn, ksks, zsks, kskdir=kskdir, zskdir=zskdir
    )

    # test soa query
    soa, rrsigs = _query_rrset(server, fqdn, dns.rdatatype.SOA)
    assert len(soa) == 1
    assert f"{zone}. {DEFAULT_TTL} IN SOA" in soa[0].to_text()
    assert len(rrsigs) > 0
    check_signatures(
        rrsigs, dns.rdatatype.SOA, fqdn, ksks, zsks, kskdir=kskdir, zskdir=zskdir
    )

    # test cdnskey query
    cdnskeys, rrsigs = _query_rrset(server, fqdn, dns.rdatatype.CDNSKEY)
    assert len(cdnskeys) > 0
    check_dnskeys(cdnskeys, ksks, zsks, kskdir=kskdir, zskdir=zskdir, cdnskey=True)
    assert len(rrsigs) > 0
    check_signatures(
        rrsigs, dns.rdatatype.CDNSKEY, fqdn, ksks, zsks, kskdir=kskdir, zskdir=zskdir
    )

    # test cds query
    cds, rrsigs = _query_rrset(server, fqdn, dns.rdatatype.CDS)
    assert len(cds) > 0
    check_cds(cds, ksks, keydir=kskdir)
    assert len(rrsigs) > 0
    check_signatures(
        rrsigs, dns.rdatatype.CDS, fqdn, ksks, zsks, kskdir=kskdir, zskdir=zskdir
    )


# pylint: disable=too-many-arguments
def check_subdomain(server, zone, ksks, zsks, kskdir=None, zskdir=None):
    # Test an RRset below the apex and verify it is signed correctly.
    fqdn = f"{zone}."
    qname = f"a.{zone}."
    qtype = dns.rdatatype.A
    response = _query(server, qname, qtype)
    assert response.rcode() == dns.rcode.NOERROR

    match = f"{qname} {DEFAULT_TTL} IN A 10.0.0.1"
    rrsigs = []
    for rrset in response.answer:
        if rrset.match(
            dns.name.from_text(qname), dns.rdataclass.IN, dns.rdatatype.RRSIG, qtype
        ):
            rrsigs.append(rrset)
        else:
            assert match in rrset.to_text()

    assert len(rrsigs) > 0
    check_signatures(rrsigs, qtype, fqdn, ksks, zsks, kskdir=kskdir, zskdir=zskdir)
