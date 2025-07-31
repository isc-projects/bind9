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

from collections import namedtuple
import os
import re
import struct
import time

from dns import dnssec, name, rdataclass, rdatatype, update

import pytest

pytest.importorskip("dns", minversion="2.0.0")
import isctest


pytestmark = pytest.mark.extra_artifacts(
    [
        "*/K*",
        "*/dsset-*",
        "*/*.bk",
        "*/*.conf",
        "*/*.db",
        "*/*.id",
        "*/*.jnl",
        "*/*.jbk",
        "*/*.key",
        "*/*.signed",
        "*/settime.out.*",
        "ans*/ans.run",
        "*/trusted.keys",
        "*/*.bad",
        "*/*.next",
        "*/*.stripped",
        "*/*.tmp",
        "*/*.stage?",
        "*/*.patched",
        "*/*.lower",
        "*/*.upper",
        "*/*.unsplit",
    ]
)


# helper functions
def grep_c(regex, filename):
    with open(filename, "r", encoding="utf-8") as f:
        blob = f.read().splitlines()
    results = [x for x in blob if re.search(regex, x)]
    return len(results)


# run dnssec-keygen
def keygen(*args):
    keygen_cmd = [os.environ.get("KEYGEN")]
    keygen_cmd.extend(args)
    return isctest.run.cmd(keygen_cmd, log_stdout=True).stdout.decode("utf-8").strip()


# run dnssec-settime
def settime(*args):
    settime_cmd = [os.environ.get("SETTIME")]
    settime_cmd.extend(args)
    return isctest.run.cmd(settime_cmd, log_stdout=True).stdout.decode("utf-8").strip()


@pytest.mark.parametrize(
    "domain",
    [
        "auto-nsec.example",
        "auto-nsec3.example",
    ],
)
def test_signing_complete(domain):
    PrivateType = namedtuple("PrivateType", ["alg", "key", "rem", "complete"])

    def convert_private(rdata) -> PrivateType:
        length = len(rdata.to_wire())
        assert length in (5, 7)
        if length == 7:
            _, key, rem, complete, alg = struct.unpack(">BHBBH", rdata.to_wire())
        else:
            alg, key, rem, complete = struct.unpack(">BHBB", rdata.to_wire())
        return PrivateType(alg, key, rem, complete)

    # query for a private type record, make sure it shows "complete"
    def check_complete():
        msg = isctest.query.create(domain, 65534)
        res = isctest.query.tcp(msg, "10.53.0.3")
        assert res.answer
        for rdata in res.answer[0]:
            record = convert_private(rdata)
            assert record.complete
        return True

    isctest.run.retry_with_timeout(check_complete, 10)


def test_split_dnssec():
    # check that split-dnssec signing worked (dnssec-signzone -D)
    msg = isctest.query.create("split-dnssec.example.", "SOA")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.rr_count_eq(res2.answer, 2)
    isctest.check.adflag(res2)

    # check that smart split-dnssec signing worked (dnssec-signzone -DS)
    msg = isctest.query.create("split-smart.example.", "SOA")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.rr_count_eq(res2.answer, 2)
    isctest.check.adflag(res2)


def test_expiring_rrsig():
    # check soon-to-expire RRSIGs without a replacement private
    # key aren't deleted. this response has to have an RRSIG:
    msg = isctest.query.create("expiring.example.", "NS")
    res = isctest.query.tcp(msg, "10.53.0.3")
    _, sigs = res.answer
    assert sigs

    # check that named doesn't loop when private keys are not available
    n = grep_c("reading private key file expiring.example", "ns3/named.run")
    assert n < 15

    # check expired signatures stay place when updates are disabled
    msg = isctest.query.create("expired.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.3")
    _, sigs = res.answer
    assert sigs


def test_apex_signing():
    # check that DNAME at apex with NSEC3 is correctly signed
    msg = isctest.query.create("dname-at-apex-nsec3.example.", "TXT")
    res = isctest.query.tcp(msg, "10.53.0.3")
    sigs = [str(a) for a in res.authority if a.rdtype == rdatatype.RRSIG]
    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    assert any(f"NSEC3 {alg} 3 600" in a for a in sigs)


def test_occluded_data():
    # check that DNSKEY and other occluded data are excluded from
    # a delegating bitmap
    msg = isctest.query.create("occluded.example.", "AXFR")
    res = isctest.query.tcp(msg, "10.53.0.3")

    n = "delegation.occluded.example."
    delegation = [r for r in res.answer if str(r.name) == n]
    assert [r for r in delegation if r.rdtype == rdatatype.DNSKEY], str(delegation)
    assert [r for r in delegation if r.rdtype == rdatatype.AAAA], str(delegation)
    nsec = [r for r in delegation if r.rdtype == rdatatype.NSEC]
    assert nsec, str(delegation)
    assert "DNSKEY" not in str(nsec[0]), str(res)
    assert "AAAA" not in str(nsec[0]), str(res)

    # check that DNSSEC records are occluded from ANY in an insecure zone
    msg = isctest.query.create("x.extrakey.example.", "ANY")
    res = isctest.query.tcp(msg, "10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    msg = isctest.query.create("z.secure.example.", "ANY")
    res = isctest.query.tcp(msg, "10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 4)  # A+RRSIG, NSEC+RRSIG


def test_update_signing():
    # minimal update test: add and delete a single record
    up = update.UpdateMessage("dynamic.example.")
    up.add("a.dynamic.example.", 300, "A", "73.80.65.49")
    res = isctest.query.tcp(up, "10.53.0.3")
    isctest.check.noerror(res)

    up = update.UpdateMessage("dynamic.example.")
    up.delete("a.dynamic.example.")
    res = isctest.query.tcp(up, "10.53.0.3")
    isctest.check.noerror(res)

    msg = isctest.query.create("a.dynamic.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res)
    isctest.check.adflag(res)

    # check that the NSEC3 record for the apex is properly signed
    # when a DNSKEY is added via UPDATE
    key = keygen(
        "-Kns3", "-q3fk", "-a", os.environ["DEFAULT_ALGORITHM"], "update-nsec3.example."
    )

    with open(f"ns3/{key}.key", "r", encoding="utf-8") as f:
        dnskey = f.read().splitlines()[-1]
        dnskey = " ".join(dnskey.split()[3:])

    up = update.UpdateMessage("update-nsec3.example.")
    up.add("update-nsec3.example.", 300, "DNSKEY", dnskey)
    res = isctest.query.tcp(up, "10.53.0.3")
    isctest.check.noerror(res)

    msg = isctest.query.create("update-nsec3.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    nsec3 = [str(a) for a in res.authority if a.rdtype == rdatatype.NSEC3]
    assert any("1 0 0 -" in a for a in nsec3)


def test_cds_signing():
    # check that CDS records are signed using KSK+ZSK by dnssec-signzone
    msg = isctest.query.create("cds.secure.", "CDS")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cds, sigs = res.answer
    assert len(sigs) == 2

    # check that CDS records are not signed using ZSK by dnssec-signzone -x
    msg = isctest.query.create("cds-x.secure.", "CDS")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cds, sigs = res.answer
    assert len(sigs) == 2  # there are two KSKs here

    # check that CDS records are signed using KSK by dnssec-policy
    msg = isctest.query.create("cds-auto.secure.", "CDS")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cds, sigs = res.answer
    assert len(sigs) == 1

    # check that CDS records are signed only using KSK when added by nsupdate
    with open("ns2/cds-update.secure.id", encoding="utf-8") as f:
        keyid = int(f.read().splitlines()[0])
    up = update.UpdateMessage("cds-update.secure.")
    up.delete("cds-update.secure.", "CDS")
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cds-update.secure.", "DNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.noerror(res)
    dnskeys, sigs = res.answer
    ksk = [a for a in dnskeys if a.flags == 257][0]
    ds = dnssec.make_ds("cds-update.secure.", ksk, 2)
    up.add("cds-update.secure.", 1, "CDS", str(ds))
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cds-update.secure.", "CDS")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cds, sig = res.answer
    assert len(cds) == 1
    assert len(sig) == 1
    assert sig[0].key_tag == keyid

    # check that CDS deletion records are signed only using KSK when
    # added by nsupdate
    up = update.UpdateMessage("cds-update.secure.")
    up.delete("cds-update.secure.", "CDS")
    up.add("cds-update.secure.", 0, "CDS", "0 0 0 00")
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cds-update.secure.", "CDS")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cds, sig = res.answer
    assert len(cds) == 1
    assert "0 0 0 00" in str(cds[0])
    assert len(sig) == 1
    assert sig[0].key_tag == keyid

    # check that a non-matching CDS record is accepted with a
    # matching CDS record. first, generate a DNSKEY with different flags:
    badksk = type(ksk)(
        ksk.rdclass, ksk.rdtype, ksk.flags + 1, ksk.protocol, ksk.algorithm, ksk.key
    )
    up = update.UpdateMessage("cds-update.secure.")
    badds = dnssec.make_ds("cds-update.secure.", badksk, 2)
    up.delete("cds-update.secure.", "CDS")
    up.add("cds-update.secure.", 1, "CDS", str(ds))
    up.add("cds-update.secure.", 1, "CDS", str(badds))
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cds-update.secure.", "CDS")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cds, sig = res.answer
    assert len(cds) == 2
    assert len(sig) == 1


def test_cdnskey_signing():
    # check that CDNSKEY records are signed using KSK+ZSK by dnssec-signzone
    msg = isctest.query.create("cdnskey.secure.", "CDNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cdnskey, sigs = res.answer
    assert len(sigs) == 2

    # check that CDNSKEY records are not signed using ZSK by dnssec-signzone -x
    msg = isctest.query.create("cdnskey-x.secure.", "CDNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cdnskey, sigs = res.answer
    assert len(sigs) == 2  # two KSKs here

    # check that CDNSKEY records are signed using KSK by dnssec-policy
    msg = isctest.query.create("cdnskey-auto.secure.", "CDNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cdnskey, sigs = res.answer
    assert len(sigs) == 1

    # check that CDNSKEY records are signed only using KSK
    # when added by nsupdate
    with open("ns2/cdnskey-update.secure.id", encoding="utf-8") as f:
        keyid = int(f.read().splitlines()[0])
    up = update.UpdateMessage("cdnskey-update.secure.")
    up.delete("cdnskey-update.secure.", "CDNSKEY")
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cdnskey-update.secure.", "DNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.noerror(res)
    dnskeys, sigs = res.answer
    ksk = [a for a in dnskeys if a.flags == 257][0]
    up.add("cdnskey-update.secure.", 1, "CDNSKEY", str(ksk))
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cdnskey-update.secure.", "CDNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cdnskey, sig = res.answer
    assert len(cdnskey) == 1
    assert len(sig) == 1
    assert sig[0].key_tag == keyid

    # check that CDNSKEY deletion records are signed only using KSK when
    # added by nsupdate
    up = update.UpdateMessage("cdnskey-update.secure.")
    up.delete("cdnskey-update.secure.", "CDNSKEY")
    up.add("cdnskey-update.secure.", 0, "CDNSKEY", "0 3 0 AA==")
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cdnskey-update.secure.", "CDNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cdnskey, sig = res.answer
    assert len(cdnskey) == 1
    assert "0 3 0 AA==" in str(cdnskey[0])
    assert len(sig) == 1
    assert sig[0].key_tag == keyid

    # check that a non-matching CDNSKEY record is accepted with a
    # matching CDNSKEY record. first, generate a DNSKEY with different flags:
    badksk = type(ksk)(
        ksk.rdclass, ksk.rdtype, ksk.flags + 1, ksk.protocol, ksk.algorithm, ksk.key
    )
    up = update.UpdateMessage("cdnskey-update.secure.")
    up.delete("cdnskey-update.secure.", "CDNSKEY")
    up.add("cdnskey-update.secure.", 1, "CDNSKEY", str(ksk))
    up.add("cdnskey-update.secure.", 1, "CDNSKEY", str(badksk))
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    msg = isctest.query.create("cdnskey-update.secure.", "CDNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.2")
    cdnskey, sig = res.answer
    assert len(cdnskey) == 2
    assert len(sig) == 1


@pytest.mark.parametrize(
    "cmd",
    [
        "signing",  # without arguments
        "signing -list",  # without zone
        "signing -clear",  # without zone
        "signing -clear all",  # without zone
    ],
)
def test_rndc_signing_except(cmd, ns3):
    # check that 'rndc signing' errors are handled
    with pytest.raises(isctest.rndc.RNDCException):
        ns3.rndc(cmd, log=False)
    ns3.rndc("status", log=False)


def test_rndc_signing_output(ns3):
    response = ns3.rndc("signing -list dynamic.example", log=False)
    assert "No signing records found" in response


def test_zonestatus_signing(ns3):
    # check that the correct resigning time is reported in zonestatus.
    # zonestatus reports a name/type and expecting resigning time;
    # we convert the time to seconds since epoch, look up the RRSIG
    # for the name and type, and check that the resigning time is
    # after the inception and before the expiration.

    response = ns3.rndc("zonestatus secure.example", log=False)

    # next resign node: secure.example/DNSKEY
    nrn = [r for r in response.splitlines() if "next resign node" in r][0]
    rdname, rdtype = nrn.split()[3].split("/")

    # next resign time: Thu, 24 Apr 2014 10:38:16 GMT
    nrt = [r for r in response.splitlines() if "next resign time" in r][0]
    rtime = " ".join(nrt.split()[3:])
    rt = time.strptime(rtime, "%a, %d %b %Y %H:%M:%S %Z")
    when = int(time.strftime("%s", rt))

    msg = isctest.query.create(rdname, rdtype)
    res = isctest.query.tcp(msg, "10.53.0.3")
    _, sigs = res.answer
    assert sigs[0].inception < when
    assert when < sigs[0].expiration


def test_offline_ksk_signing(ns2):
    def getfrom(file):
        with open(file, encoding="utf-8") as f:
            return f.read().strip()

    def getkeyid(key: str):
        m = re.match(r"K.*\+\d*\+(\d*)", key)
        return int(m.group(1))

    def check_signing_keys(types: list[str], expect: list[str], prohibit: list[str]):
        for qtype in types:
            isctest.log.debug(f"checking signing keys for {qtype}")
            msg = isctest.query.create(zone, qtype)
            res = isctest.query.tcp(msg, "10.53.0.2")
            assert res.answer, str(res)
            rrset = res.get_rrset(
                res.answer,
                name.from_text(f"{zone}."),
                rdataclass.IN,
                rdatatype.RRSIG,
                rdatatype.RdataType.make(qtype),
            )
            assert rrset, f"expected RRSIG({qtype}) missing from ANSWER" + str(res)
            keys = {rr.key_tag for rr in rrset}
            assert len(keys) == 1, str(res)
            for exp in expect:
                assert exp in keys
            for proh in prohibit:
                assert proh not in keys
            return True

    def check_zskcount():
        msg = isctest.query.create(zone, "DNSKEY")
        res = isctest.query.tcp(msg, "10.53.0.2")
        dnskeys, _ = res.answer
        zskcount = len([rr for rr in dnskeys if rr.flags == 256])
        assert zskcount == 2, str(res)
        return True

    def ksk_remove():
        isctest.log.info("remove the KSK from disk")
        os.rename(f"ns2/{KSK}.key", f"ns2/{KSK}.key.bak")
        os.rename(f"ns2/{KSK}.private", f"ns2/{KSK}.private.bak")

    def ksk_recover():
        isctest.log.info("put back the KSK")
        os.rename(f"ns2/{KSK}.key.bak", f"ns2/{KSK}.key")
        os.rename(f"ns2/{KSK}.private.bak", f"ns2/{KSK}.private")

    def loadkeys():
        pattern = re.compile(f"{zone}/IN.*next key event")
        with ns2.watch_log_from_here() as watcher:
            ns2.rndc(f"loadkeys {zone}", log=False)
            watcher.wait_for_line(pattern)

    ksk_only_types = ["DNSKEY", "CDNSKEY", "CDS"]

    zone = "updatecheck-kskonly.secure"
    KSK = getfrom(f"ns2/{zone}.ksk.key")
    ZSK = getfrom(f"ns2/{zone}.zsk.key")
    KSKID = int(getfrom(f"ns2/{zone}.ksk.id"))
    ZSKID = int(getfrom(f"ns2/{zone}.zsk.id"))

    # set key state for KSK. the ZSK rollovers below assume that there is a
    # chain of trust established, so we tell named that the DS is in
    # omnipresent state.
    settime("-s", "-d", "OMNIPRESENT", "now", "-Kns2", KSK)

    isctest.log.info("check state before KSK is made offline")
    isctest.log.info("make sure certain types are signed with KSK only")
    check_signing_keys(ksk_only_types, expect=[KSKID], prohibit=[ZSKID])

    isctest.log.info("check SOA is signed with ZSK only")
    check_signing_keys(["SOA"], expect=[ZSKID], prohibit=[KSKID])

    isctest.log.info("roll the ZSK")
    ZSK2 = keygen(
        "-qKns2",
        "-Pnone",
        "-Anone",
        "-a",
        os.environ["DEFAULT_ALGORITHM"],
        "-b",
        os.environ["DEFAULT_BITS"],
        zone,
    )
    ZSKID2 = getkeyid(ZSK2)

    isctest.log.info("prepublish new ZSK")
    ns2.rndc(f"dnssec -rollover -key {ZSKID} {zone}", log=False)
    isctest.run.retry_with_timeout(check_zskcount, 5)

    isctest.log.info("make the new ZSK active")
    settime("-sKns2", "-Inow", ZSK)
    settime("-sKns2", "-Anow", "-k", "OMNIPRESENT", "now", ZSK2)
    loadkeys()

    with ns2.watch_log_from_start() as watcher:
        watcher.wait_for_line(
            [f"{ZSKID2} (ZSK) is now active", f"{ZSKID} (ZSK) is now inactive"]
        )

    ksk_remove()

    isctest.log.info("update the zone, requiring a resign of the SOA RRset")
    up = update.UpdateMessage(f"{zone}.")
    up.add(f"{zone}.", 300, "TXT", "added by UPDATE")
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    isctest.log.info(
        "redo the tests now that the zone is updated and the KSK is offline"
    )
    isctest.log.info("make sure certain types are signed with KSK only")
    check_signing_keys(ksk_only_types, expect=[KSKID], prohibit=[ZSKID, ZSKID2])

    isctest.log.info("check TXT, SOA are signed with ZSK2 only")

    def check_txt_soa_zsk2():
        return check_signing_keys(
            ["TXT", "SOA"], expect=[ZSKID2], prohibit=[KSKID, ZSKID]
        )

    isctest.run.retry_with_timeout(check_txt_soa_zsk2, 5)

    ksk_recover()

    isctest.log.info("roll the ZSK again")
    ZSK3 = keygen(
        "-qKns2",
        "-Pnone",
        "-Anone",
        "-a",
        os.environ["DEFAULT_ALGORITHM"],
        "-b",
        os.environ["DEFAULT_BITS"],
        zone,
    )
    ZSKID3 = getkeyid(ZSK3)

    isctest.log.info("delete old ZSK, schedule ZSK2 inactive, pre-publish ZSK3")
    settime("-sKns2", "-k", "HIDDEN", "now", "-z", "HIDDEN", "now", "-Dnow", ZSK)
    settime("-sKns2", "-k", "OMNIPRESENT", "now", "-z", "OMNIPRESENT", "now", ZSK2)
    loadkeys()
    ns2.rndc(f"dnssec -rollover -key {ZSKID2} {zone}", log=False)

    with ns2.watch_log_from_start() as watcher:
        watcher.wait_for_line(f"{ZSKID3} (ZSK) is now published")

    ksk_remove()

    isctest.log.info("update the zone again, requiring a resign of the SOA RRset")
    up = update.UpdateMessage(f"{zone}.")
    up.add(f"{zone}.", 300, "TXT", "added by UPDATE again")
    up.add(f"{zone}.", 300, "A", "1.2.3.4")
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    isctest.log.info("redo the tests now that the ZSK roll has deleted the old key")

    isctest.log.info("make sure certain types are signed with KSK only")
    check_signing_keys(ksk_only_types, expect=[KSKID], prohibit=[ZSKID, ZSKID2, ZSKID3])

    isctest.log.info("check A, TXT, SOA are signed with ZSK2 only")

    def check_a_txt_soa_zsk2():
        return check_signing_keys(
            ["A", "TXT", "SOA"], expect=[ZSKID2], prohibit=[KSKID, ZSKID, ZSKID3]
        )

    isctest.run.retry_with_timeout(check_a_txt_soa_zsk2, 5)

    ksk_recover()

    isctest.log.info("make ZSK3 active")
    settime("-sKns2", "-Inow", ZSK2)
    settime("-sKns2", "-k", "OMNIPRESENT", "now", "-Anow", ZSK3)
    loadkeys()

    with ns2.watch_log_from_start() as watcher:
        watcher.wait_for_line(
            [f"{ZSKID3} (ZSK) is now active", f"{ZSKID2} (ZSK) is now inactive"]
        )

    ksk_remove()

    isctest.log.info("update the zone again, requiring a resign of the SOA RRset")
    up = update.UpdateMessage(f"{zone}.")
    up.add(f"{zone}.", 300, "TXT", "added by UPDATE one more time")
    up.add(f"{zone}.", 300, "A", "4.3.2.1")
    up.add(f"{zone}.", 300, "AAAA", "dead::beef")
    res = isctest.query.tcp(up, "10.53.0.2")
    isctest.check.noerror(res)

    isctest.log.info("redo the tests one last time")
    isctest.log.info("make sure certain types are signed with KSK only")
    check_signing_keys(ksk_only_types, expect=[KSKID], prohibit=[ZSKID, ZSKID2, ZSKID3])

    isctest.log.info("check A, TXT, SOA are signed with ZSK2 only")

    def check_aaaa_a_txt_soa_zsk3():
        return check_signing_keys(
            ["AAAA", "A", "TXT", "SOA"],
            expect=[ZSKID3],
            prohibit=[KSKID, ZSKID, ZSKID2],
        )

    isctest.run.retry_with_timeout(check_aaaa_a_txt_soa_zsk3, 5)
