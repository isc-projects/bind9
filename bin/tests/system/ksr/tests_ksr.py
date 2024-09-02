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

# pylint: disable=too-many-lines

import os
import shutil
import time

from datetime import datetime

import isctest

from isctest.kasp import (
    addtime,
    cds_equals,
    dnskey_equals,
    get_keytag,
    get_metadata,
    get_timing_metadata,
)


def between(value, start, end):
    if int(value) == 0:
        return False

    return int(value) > int(start) and int(value) < int(end)


def file_contents_equal(file1, file2):
    diff_command = [
        "diff",
        "-w",
        file1,
        file2,
    ]
    isctest.run.cmd(diff_command)


def keygen(zone, policy, keydir, when="now"):
    keygen_command = [
        *os.environ.get("KEYGEN").split(),
        "-l",
        "ns1/named.conf",
        "-fK",
        "-K",
        keydir,
        "-k",
        policy,
        "-P",
        when,
        "-A",
        when,
        "-P",
        "sync",
        when,
        zone,
    ]
    output = isctest.run.cmd(keygen_command, log_stdout=True).stdout.decode("utf-8")
    keys = output.split()
    return keys


def ksr(zone, policy, action, options="", raise_on_exception=True):
    ksr_command = [
        *os.environ.get("KSR").split(),
        "-l",
        "ns1/named.conf",
        "-k",
        policy,
        *options.split(),
        action,
        zone,
    ]

    out = isctest.run.cmd(
        ksr_command, log_stdout=True, raise_on_exception=raise_on_exception
    )
    return out.stdout.decode("utf-8"), out.stderr.decode("utf-8")


# pylint: disable=too-many-arguments,too-many-branches,too-many-locals,too-many-statements
def check_keys(keys, lifetime, alg, size, keydir=None, offset=0, with_state=False):
    # Check keys that were created.
    inception = 0
    num = 0

    now = datetime.now().strftime("%Y%m%d%H%M%S")

    for key in keys:
        if keydir is not None:
            statefile = f"{keydir}/{key}.state"
        else:
            statefile = f"{key}.state"

        # created: from keyfile plus offset
        created = get_timing_metadata(key, "Created", keydir=keydir, offset=offset)

        # active: retired previous key
        if num == 0:
            active = created
        else:
            active = retired

        # published: 2h5m (dnskey-ttl + publish-safety + propagation)
        published = addtime(active, -7500)

        # retired: zsk-lifetime
        if lifetime > 0:
            retired = addtime(active, lifetime)
            # removed: 10d1h5m
            # (ttlsig + retire-safety + sign-delay + propagation)
            removed = addtime(retired, 867900)
        else:
            retired = 0
            removed = 0

        if between(now, published, retired) or int(retired) == 0:
            goal = "omnipresent"
            pubdelay = addtime(published, 7500)
            signdelay = addtime(active, 867900)

            if between(now, published, pubdelay):
                state_dnskey = "rumoured"
            else:
                state_dnskey = "omnipresent"

            if between(now, active, signdelay):
                state_zrrsig = "rumoured"
            else:
                state_zrrsig = "omnipresent"
        else:
            goal = "hidden"
            state_dnskey = "hidden"
            state_zrrsig = "hidden"

        with open(statefile, "r", encoding="utf-8") as file:
            metadata = file.read()
            assert f"Algorithm: {alg}" in metadata
            assert f"Length: {size}" in metadata
            assert f"Lifetime: {lifetime}" in metadata
            assert "KSK: no" in metadata
            assert "ZSK: yes" in metadata
            assert f"Published: {published}" in metadata
            assert f"Active: {active}" in metadata

            if lifetime > 0:
                assert f"Retired: {retired}" in metadata
                assert f"Removed: {removed}" in metadata
            else:
                assert "Retired:" not in metadata
                assert "Removed:" not in metadata

            if with_state:
                assert f"GoalState: {goal}" in metadata
                assert f"DNSKEYState: {state_dnskey}" in metadata
                assert f"ZRRSIGState: {state_zrrsig}" in metadata
                assert "KRRSIGState:" not in metadata
                assert "DSState:" not in metadata

        inception += lifetime
        num += 1


def check_keysigningrequest(out, zsks, start, end, keydir=None):
    lines = out.split("\n")
    line_no = 0

    inception = start
    while int(inception) < int(end):
        next_bundle = addtime(end, 1)
        # expect bundle header
        assert f";; KeySigningRequest 1.0 {inception}" in lines[line_no]
        line_no += 1
        # expect zsks
        for key in sorted(zsks):
            published = get_timing_metadata(key, "Publish", keydir=keydir)
            if between(published, inception, next_bundle):
                next_bundle = published

            removed = get_timing_metadata(
                key, "Delete", keydir=keydir, must_exist=False
            )
            if between(removed, inception, next_bundle):
                next_bundle = removed

            if int(published) > int(inception):
                continue
            if int(removed) != 0 and int(inception) >= int(removed):
                continue

            # this zsk must be in the ksr
            assert dnskey_equals(key, lines[line_no], keydir=keydir)
            line_no += 1

        inception = next_bundle

    # ksr footer
    assert ";; KeySigningRequest 1.0 generated at" in lines[line_no]
    line_no += 1

    # trailing empty lines
    while line_no < len(lines):
        assert lines[line_no] == ""
        line_no += 1

    assert line_no == len(lines)


# pylint: disable=too-many-arguments,too-many-branches,too-many-locals,too-many-statements
def check_signedkeyresponse(
    out,
    zone,
    ksks,
    zsks,
    start,
    end,
    refresh,
    kskdir=None,
    zskdir=None,
    cdnskey=True,
    cds="SHA-256",
):
    lines = out.split("\n")
    line_no = 0
    next_bundle = addtime(end, 1)

    inception = start
    while int(inception) < int(end):
        # A single signed key response may consist of:
        # ;; SignedKeyResponse (header)
        # ;; DNSKEY 257 (one per published key in ksks)
        # ;; DNSKEY 256 (one per published key in zsks)
        # ;; RRSIG(DNSKEY) (one per active key in ksks)
        # ;; CDNSKEY (one per published key in ksks)
        # ;; RRSIG(CDNSKEY) (one per active key in ksks)
        # ;; CDS (one per published key in ksks)
        # ;; RRSIG(CDS) (one per active key in ksks)

        sigstart = addtime(inception, -3600)  # clockskew: 1 hour
        sigend = addtime(inception, 1209600)  # sig-validity: 14 days
        next_bundle = addtime(sigend, refresh)

        # ignore empty lines
        while line_no < len(lines):
            if lines[line_no] == "":
                line_no += 1
            else:
                break

        # expect bundle header
        assert f";; SignedKeyResponse 1.0 {inception}" in lines[line_no]
        line_no += 1

        # expect ksks
        for key in sorted(ksks):
            published = get_timing_metadata(key, "Publish", keydir=kskdir)
            removed = get_timing_metadata(
                key, "Delete", keydir=kskdir, must_exist=False
            )

            if int(published) > int(inception):
                continue
            if int(removed) != 0 and int(inception) >= int(removed):
                continue

            # this ksk must be in the ksr
            assert dnskey_equals(key, lines[line_no], keydir=kskdir)
            line_no += 1

        # expect zsks
        for key in sorted(zsks):
            published = get_timing_metadata(key, "Publish", keydir=zskdir)
            if between(published, inception, next_bundle):
                next_bundle = published

            removed = get_timing_metadata(
                key, "Delete", keydir=zskdir, must_exist=False
            )
            if between(removed, inception, next_bundle):
                next_bundle = removed

            if int(published) > int(inception):
                continue
            if int(removed) != 0 and int(inception) >= int(removed):
                continue

            # this zsk must be in the ksr
            assert dnskey_equals(key, lines[line_no], keydir=zskdir)
            line_no += 1

        # expect rrsig(dnskey)
        for key in sorted(ksks):
            active = get_timing_metadata(key, "Activate", keydir=kskdir)
            inactive = get_timing_metadata(
                key, "Inactive", keydir=kskdir, must_exist=False
            )
            if int(active) > int(inception):
                continue
            if int(inactive) != 0 and int(inception) >= int(inactive):
                continue

            # there must be a signature of this ksk
            keytag = get_keytag(key)
            alg = get_metadata(key, "Algorithm", keydir=kskdir)
            expect = f"{zone}. 3600 IN RRSIG DNSKEY {alg} 2 3600 {sigend} {sigstart} {keytag} {zone}."
            rrsig = " ".join(lines[line_no].split())
            assert expect in rrsig
            line_no += 1

        # expect cdnskey
        if cdnskey:
            for key in sorted(ksks):
                published = get_timing_metadata(key, "Publish", keydir=kskdir)
                removed = get_timing_metadata(
                    key, "Delete", keydir=kskdir, must_exist=False
                )
                if int(published) > int(inception):
                    continue
                if int(removed) != 0 and int(inception) >= int(removed):
                    continue

                # the cdnskey of this ksk must be in the ksr
                assert dnskey_equals(key, lines[line_no], keydir=kskdir, cdnskey=True)
                line_no += 1

            # expect rrsig(cdnskey)
            for key in sorted(ksks):
                active = get_timing_metadata(key, "Activate", keydir=kskdir)
                inactive = get_timing_metadata(
                    key, "Inactive", keydir=kskdir, must_exist=False
                )
                if int(active) > int(inception):
                    continue
                if int(inactive) != 0 and int(inception) >= int(inactive):
                    continue

                # there must be a signature of this ksk
                keytag = get_keytag(key)
                alg = get_metadata(key, "Algorithm", keydir=kskdir)
                expect = f"{zone}. 3600 IN RRSIG CDNSKEY {alg} 2 3600 {sigend} {sigstart} {keytag} {zone}."
                rrsig = " ".join(lines[line_no].split())
                assert expect in rrsig
                line_no += 1

        # expect cds
        if cds != "":
            for key in sorted(ksks):
                published = get_timing_metadata(key, "Publish", keydir=kskdir)
                removed = get_timing_metadata(
                    key, "Delete", keydir=kskdir, must_exist=False
                )
                if int(published) > int(inception):
                    continue
                if int(removed) != 0 and int(inception) >= int(removed):
                    continue

                # the cds of this ksk must be in the ksr
                expected_cds = cds.split(",")
                for alg in expected_cds:
                    assert cds_equals(key, lines[line_no], alg.strip(), keydir=kskdir)
                    line_no += 1

            # expect rrsig(cds)
            for key in sorted(ksks):
                active = get_timing_metadata(key, "Activate", keydir=kskdir)
                inactive = get_timing_metadata(
                    key, "Inactive", keydir=kskdir, must_exist=False
                )
                if int(active) > int(inception):
                    continue
                if int(inactive) != 0 and int(inception) >= int(inactive):
                    continue

                # there must be a signature of this ksk
                keytag = get_keytag(key)
                alg = get_metadata(key, "Algorithm", keydir=kskdir)
                expect = f"{zone}. 3600 IN RRSIG CDS {alg} 2 3600 {sigend} {sigstart} {keytag} {zone}."
                rrsig = " ".join(lines[line_no].split())
                assert expect in rrsig
                line_no += 1

        inception = next_bundle

    # skr footer
    assert ";; SignedKeyResponse 1.0 generated at" in lines[line_no]
    line_no += 1

    # trailing empty lines
    while line_no < len(lines):
        assert lines[line_no] == ""
        line_no += 1

    assert line_no == len(lines)


def test_ksr_errors():
    # check that 'dnssec-ksr' errors on unknown action
    _, err = ksr("common.test", "common", "foobar", raise_on_exception=False)
    assert "dnssec-ksr: fatal: unknown command 'foobar'" in err

    # check that 'dnssec-ksr keygen' errors on missing end date
    _, err = ksr("common.test", "common", "keygen", raise_on_exception=False)
    assert "dnssec-ksr: fatal: keygen requires an end date" in err

    # check that 'dnssec-ksr keygen' errors on zone with csk
    _, err = ksr(
        "csk.test", "csk", "keygen", options="-K ns1 -e +2y", raise_on_exception=False
    )
    assert "dnssec-ksr: fatal: policy 'csk' has no zsks" in err

    # check that 'dnssec-ksr request' errors on missing end date
    _, err = ksr("common.test", "common", "request", raise_on_exception=False)
    assert "dnssec-ksr: fatal: request requires an end date" in err

    # check that 'dnssec-ksr sign' errors on missing ksr file
    _, err = ksr(
        "common.test",
        "common",
        "sign",
        options="-K ns1/offline -i now -e +1y",
        raise_on_exception=False,
    )
    assert "dnssec-ksr: fatal: 'sign' requires a KSR file" in err


# pylint: disable=too-many-locals,too-many-statements
def test_ksr_common(servers):
    # common test cases (1)
    zone = "common.test"
    policy = "common"
    n = 1

    # create ksk
    ksks = keygen(zone, policy, "ns1/offline")
    assert len(ksks) == 1

    # check that 'dnssec-ksr keygen' pregenerates right amount of keys
    out, _ = ksr(zone, policy, "keygen", options="-i now -e +1y")
    zsks = out.split()
    assert len(zsks) == 2

    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    size = os.environ.get("DEFAULT_BITS")
    lifetime = 16070400
    check_keys(zsks, lifetime, alg, size)

    # check that 'dnssec-ksr keygen' pregenerates right amount of keys
    # in the given key directory
    out, _ = ksr(zone, policy, "keygen", options="-K ns1 -i now -e +1y")
    zsks = out.split()
    assert len(zsks) == 2

    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    size = os.environ.get("DEFAULT_BITS")
    lifetime = 16070400
    check_keys(zsks, lifetime, alg, size, keydir="ns1")

    for key in zsks:
        privatefile = f"ns1/{key}.private"
        keyfile = f"ns1/{key}.key"
        statefile = f"ns1/{key}.state"
        shutil.copyfile(privatefile, f"{privatefile}.backup")
        shutil.copyfile(keyfile, f"{keyfile}.backup")
        shutil.copyfile(statefile, f"{statefile}.backup")

    # check that 'dnssec-ksr request' creates correct ksr
    now = get_timing_metadata(zsks[0], "Created", keydir="ns1")
    until = addtime(now, 31536000)  # 1 year
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {now} -e +1y")

    fname = f"{zone}.ksr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    check_keysigningrequest(out, zsks, now, until, keydir="ns1")

    # check that 'dnssec-ksr sign' creates correct skr
    out, _ = ksr(
        zone, policy, "sign", options=f"-K ns1/offline -f {fname} -i {now} -e +1y"
    )

    fname = f"{zone}.skr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out, zone, ksks, zsks, now, until, refresh, kskdir="ns1/offline", zskdir="ns1"
    )

    # common test cases (2)
    n = 2

    # check that 'dnssec-ksr keygen' selects pregenerated keys for
    # the same time bundle
    out, _ = ksr(zone, policy, "keygen", options=f"-K ns1 -i {now} -e +1y")
    selected_zsks = out.split()
    assert len(selected_zsks) == 2
    for index, key in enumerate(selected_zsks):
        assert zsks[index] == key
        file_contents_equal(f"ns1/{key}.private", f"ns1/{key}.private.backup")
        file_contents_equal(f"ns1/{key}.key", f"ns1/{key}.key.backup")
        file_contents_equal(f"ns1/{key}.state", f"ns1/{key}.state.backup")

    # check that 'dnssec-ksr keygen' generates only necessary keys for
    # overlapping time bundle
    out, err = ksr(zone, policy, "keygen", options=f"-K ns1 -i {now} -e +2y -v 1")
    overlapping_zsks = out.split()
    assert len(overlapping_zsks) == 4

    verbose = err.split()
    selected = 0
    generated = 0
    for output in verbose:
        if "Selecting" in output:
            selected += 1
        if "Generating" in output:
            generated += 1
    assert selected == 2
    assert generated == 2
    for index, key in enumerate(overlapping_zsks):
        if index < 2:
            assert zsks[index] == key
            file_contents_equal(f"ns1/{key}.private", f"ns1/{key}.private.backup")
            file_contents_equal(f"ns1/{key}.key", f"ns1/{key}.key.backup")
            file_contents_equal(f"ns1/{key}.state", f"ns1/{key}.state.backup")

    # run 'dnssec-ksr keygen' again with verbosity 0
    out, _ = ksr(zone, policy, "keygen", options=f"-K ns1 -i {now} -e +2y")
    overlapping_zsks2 = out.split()
    assert len(overlapping_zsks2) == 4
    check_keys(overlapping_zsks2, lifetime, alg, size, keydir="ns1")
    for index, key in enumerate(overlapping_zsks2):
        assert overlapping_zsks[index] == key

    # check that 'dnssec-ksr request' creates correct ksr if the
    # interval is shorter
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {now} -e +1y")

    fname = f"{zone}.ksr.{n}.shorter"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    check_keysigningrequest(out, zsks, now, until, keydir="ns1")

    # check that 'dnssec-ksr request' creates correct ksr with new interval
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {now} -e +2y")

    fname = f"{zone}.ksr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    until = addtime(now, 63072000)  # 2 years
    check_keysigningrequest(out, overlapping_zsks, now, until, keydir="ns1")

    # check that 'dnssec-ksr request' errors if there are not enough keys
    _, err = ksr(
        zone,
        policy,
        "request",
        options=f"-K ns1 -i {now} -e +3y",
        raise_on_exception=False,
    )
    error = f"no {zone}/ECDSAP256SHA256 zsk key pair found for bundle"
    assert f"dnssec-ksr: fatal: {error}" in err

    # check that 'dnssec-ksr sign' creates correct skr
    out, _ = ksr(
        zone, policy, "sign", options=f"-K ns1/offline -f {fname} -i {now} -e +2y"
    )

    fname = f"{zone}.skr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out,
        zone,
        ksks,
        overlapping_zsks,
        now,
        until,
        refresh,
        kskdir="ns1/offline",
        zskdir="ns1",
    )

    # add zone
    ns1 = servers["ns1"]
    ns1.rndc(
        f"addzone {zone} "
        + "{ type primary; file "
        + f'"{zone}.db"; dnssec-policy {policy}; '
        + "};",
        log=False,
    )

    # import skr
    shutil.copyfile(fname, f"ns1/{fname}")
    ns1.rndc(f"skr -import {fname} {zone}", log=False)

    # test zone is correctly signed
    # - check rndc dnssec -status output
    isctest.kasp.check_dnssecstatus(ns1, zone, overlapping_zsks, policy=policy)
    # - zone is signed
    isctest.kasp.zone_is_signed(ns1, zone)
    # - dnssec_verify
    isctest.kasp.dnssec_verify(ns1, zone)
    # - check keys
    check_keys(overlapping_zsks, lifetime, alg, size, keydir="ns1", with_state=True)
    # - check apex
    isctest.kasp.check_apex(
        ns1, zone, ksks, overlapping_zsks, kskdir="ns1/offline", zskdir="ns1"
    )
    # - check subdomain
    isctest.kasp.check_subdomain(
        ns1, zone, ksks, overlapping_zsks, kskdir="ns1/offline", zskdir="ns1"
    )


# pylint: disable=too-many-locals
def test_ksr_lastbundle(servers):
    zone = "last-bundle.test"
    policy = "common"
    n = 1

    # create ksk
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    offset = -31536000
    when = addtime(now, offset)
    when = addtime(when, -86400)
    ksks = keygen(zone, policy, "ns1/offline", when=when)
    assert len(ksks) == 1

    # check that 'dnssec-ksr keygen' pregenerates right amount of keys
    out, _ = ksr(zone, policy, "keygen", options="-K ns1 -i -1y -e +1d")
    zsks = out.split()
    assert len(zsks) == 2

    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    size = os.environ.get("DEFAULT_BITS")
    lifetime = 16070400
    check_keys(zsks, lifetime, alg, size, keydir="ns1", offset=offset)

    # check that 'dnssec-ksr request' creates correct ksr
    then = get_timing_metadata(zsks[0], "Created", keydir="ns1")
    then = addtime(then, offset)
    until = addtime(then, 31622400)  # 1 year, 1 day
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {then} -e +1d")

    fname = f"{zone}.ksr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    check_keysigningrequest(out, zsks, then, until, keydir="ns1")

    # check that 'dnssec-ksr sign' creates correct skr
    out, _ = ksr(
        zone, policy, "sign", options=f"-K ns1/offline -f {fname} -i {then} -e +1d"
    )

    fname = f"{zone}.skr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out, zone, ksks, zsks, then, until, refresh, kskdir="ns1/offline", zskdir="ns1"
    )

    # add zone
    ns1 = servers["ns1"]
    ns1.rndc(
        f"addzone {zone} "
        + "{ type primary; file "
        + f'"{zone}.db"; dnssec-policy {policy}; '
        + "};",
        log=False,
    )

    # import skr
    shutil.copyfile(fname, f"ns1/{fname}")
    ns1.rndc(f"skr -import {fname} {zone}", log=False)

    # test zone is correctly signed
    # - check rndc dnssec -status output
    isctest.kasp.check_dnssecstatus(ns1, zone, zsks, policy=policy)
    # - zone is signed
    isctest.kasp.zone_is_signed(ns1, zone)
    # - dnssec_verify
    isctest.kasp.dnssec_verify(ns1, zone)
    # - check keys
    check_keys(zsks, lifetime, alg, size, keydir="ns1", offset=offset, with_state=True)
    # - check apex
    isctest.kasp.check_apex(ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1")
    # - check subdomain
    isctest.kasp.check_subdomain(
        ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1"
    )

    # check that last bundle warning is logged
    warning = "last bundle in skr, please import new skr file"
    assert f"zone {zone}/IN (signed): zone_rekey: {warning}" in ns1.log


# pylint: disable=too-many-locals
def test_ksr_inthemiddle(servers):
    zone = "in-the-middle.test"
    policy = "common"
    n = 1

    # create ksk
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    offset = -31536000
    when = addtime(now, offset)
    when = addtime(when, -86400)
    ksks = keygen(zone, policy, "ns1/offline", when=when)
    assert len(ksks) == 1

    # check that 'dnssec-ksr keygen' pregenerates right amount of keys
    out, _ = ksr(zone, policy, "keygen", options="-K ns1 -i -1y -e +1y")
    zsks = out.split()
    assert len(zsks) == 4

    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    size = os.environ.get("DEFAULT_BITS")
    lifetime = 16070400
    check_keys(zsks, lifetime, alg, size, keydir="ns1", offset=offset)

    # check that 'dnssec-ksr request' creates correct ksr
    then = get_timing_metadata(zsks[0], "Created", keydir="ns1")
    then = addtime(then, offset)
    until = addtime(then, 63072000)  # 2 years
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {then} -e +1y")

    fname = f"{zone}.ksr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    check_keysigningrequest(out, zsks, then, until, keydir="ns1")

    # check that 'dnssec-ksr sign' creates correct skr
    out, _ = ksr(
        zone, policy, "sign", options=f"-K ns1/offline -f {fname} -i {then} -e +1y"
    )

    fname = f"{zone}.skr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out, zone, ksks, zsks, then, until, refresh, kskdir="ns1/offline", zskdir="ns1"
    )

    # add zone
    ns1 = servers["ns1"]
    ns1.rndc(
        f"addzone {zone} "
        + "{ type primary; file "
        + f'"{zone}.db"; dnssec-policy {policy}; '
        + "};",
        log=False,
    )

    # import skr
    shutil.copyfile(fname, f"ns1/{fname}")
    ns1.rndc(f"skr -import {fname} {zone}", log=False)

    # test zone is correctly signed
    # - check rndc dnssec -status output
    isctest.kasp.check_dnssecstatus(ns1, zone, zsks, policy=policy)
    # - zone is signed
    isctest.kasp.zone_is_signed(ns1, zone)
    # - dnssec_verify
    isctest.kasp.dnssec_verify(ns1, zone)
    # - check keys
    check_keys(zsks, lifetime, alg, size, keydir="ns1", offset=offset, with_state=True)
    # - check apex
    isctest.kasp.check_apex(ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1")
    # - check subdomain
    isctest.kasp.check_subdomain(
        ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1"
    )

    # check that no last bundle warning is logged
    warning = "last bundle in skr, please import new skr file"
    assert f"zone {zone}/IN (signed): zone_rekey: {warning}" not in ns1.log


# pylint: disable=too-many-locals
def check_ksr_rekey_logs_error(server, zone, policy, offset, end):
    n = 1

    # create ksk
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    then = addtime(now, offset)
    until = addtime(now, end)
    ksks = keygen(zone, policy, "ns1/offline", when=then)
    assert len(ksks) == 1

    # key generation
    out, _ = ksr(zone, policy, "keygen", options=f"-K ns1 -i {then} -e {until}")
    zsks = out.split()
    assert len(zsks) == 2

    # create request
    now = get_timing_metadata(zsks[0], "Created", keydir="ns1")
    then = addtime(now, offset)
    until = addtime(now, end)
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {then} -e {until}")

    fname = f"{zone}.ksr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    # sign request
    out, _ = ksr(
        zone, policy, "sign", options=f"-K ns1/offline -f {fname} -i {then} -e {until}"
    )

    fname = f"{zone}.skr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    # add zone
    server.rndc(
        f"addzone {zone} "
        + "{ type primary; file "
        + f'"{zone}.db"; dnssec-policy {policy}; '
        + "};",
        log=False,
    )

    # import skr
    shutil.copyfile(fname, f"ns1/{fname}")
    server.rndc(f"skr -import {fname} {zone}", log=False)

    # test that rekey logs error
    time_remaining = 10
    warning = "no available SKR bundle"
    line = f"zone {zone}/IN (signed): zone_rekey failure: {warning}"
    while time_remaining > 0:
        if line not in server.log:
            time_remaining -= 1
            time.sleep(1)
        else:
            break
    assert line in server.log


def test_ksr_rekey_logs_error(servers):
    # check that an SKR that is too old logs error
    check_ksr_rekey_logs_error(
        servers["ns1"], "past.test", "common", -63072000, -31536000
    )
    # check that an SKR that is too new logs error
    check_ksr_rekey_logs_error(
        servers["ns1"], "future.test", "common", 2592000, 31536000
    )


# pylint: disable=too-many-locals
def test_ksr_unlimited(servers):
    zone = "unlimited.test"
    policy = "unlimited"
    n = 1

    # create ksk
    ksks = keygen(zone, policy, "ns1/offline")
    assert len(ksks) == 1

    # check that 'dnssec-ksr keygen' pregenerates right amount of keys
    out, _ = ksr(zone, policy, "keygen", options="-K ns1 -i now -e +2y")
    zsks = out.split()
    assert len(zsks) == 1

    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    size = os.environ.get("DEFAULT_BITS")
    lifetime = 0
    check_keys(zsks, lifetime, alg, size, keydir="ns1")

    # check that 'dnssec-ksr request' creates correct ksr
    now = get_timing_metadata(zsks[0], "Created", keydir="ns1")
    until = addtime(now, 4 * 31536000)  # 4 years
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {now} -e +4y")

    fname = f"{zone}.ksr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    check_keysigningrequest(out, zsks, now, until, keydir="ns1")

    # check that 'dnssec-ksr sign' creates correct skr without cdnskey
    out, _ = ksr(
        zone, "no-cdnskey", "sign", options=f"-K ns1/offline -f {fname} -i {now} -e +4y"
    )

    skrfile = f"{zone}.no-cdnskey.skr.{n}"
    with open(skrfile, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out,
        zone,
        ksks,
        zsks,
        now,
        until,
        refresh,
        kskdir="ns1/offline",
        zskdir="ns1",
        cdnskey=False,
        cds="SHA-1, SHA-256, SHA-384",
    )

    # check that 'dnssec-ksr sign' creates correct skr without cds
    out, _ = ksr(
        zone, "no-cds", "sign", options=f"-K ns1/offline -f {fname} -i {now} -e +4y"
    )

    skrfile = f"{zone}.no-cds.skr.{n}"
    with open(skrfile, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out,
        zone,
        ksks,
        zsks,
        now,
        until,
        refresh,
        kskdir="ns1/offline",
        zskdir="ns1",
        cds="",
    )

    # check that 'dnssec-ksr sign' creates correct skr
    out, _ = ksr(
        zone, policy, "sign", options=f"-K ns1/offline -f {fname} -i {now} -e +4y"
    )

    skrfile = f"{zone}.{policy}.skr.{n}"
    with open(skrfile, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out, zone, ksks, zsks, now, until, refresh, kskdir="ns1/offline", zskdir="ns1"
    )

    # add zone
    ns1 = servers["ns1"]
    ns1.rndc(
        f"addzone {zone} "
        + "{ type primary; file "
        + f'"{zone}.db"; dnssec-policy {policy}; '
        + "};",
        log=False,
    )

    # import skr
    shutil.copyfile(skrfile, f"ns1/{skrfile}")
    ns1.rndc(f"skr -import {skrfile} {zone}", log=False)

    # test zone is correctly signed
    # - check rndc dnssec -status output
    isctest.kasp.check_dnssecstatus(ns1, zone, zsks, policy=policy)
    # - zone is signed
    isctest.kasp.zone_is_signed(ns1, zone)
    # - dnssec_verify
    isctest.kasp.dnssec_verify(ns1, zone)
    # - check keys
    check_keys(zsks, lifetime, alg, size, keydir="ns1", with_state=True)
    # - check apex
    isctest.kasp.check_apex(ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1")
    # - check subdomain
    isctest.kasp.check_subdomain(
        ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1"
    )


# pylint: disable=too-many-locals
def test_ksr_twotone(servers):
    zone = "two-tone.test"
    policy = "two-tone"
    n = 1

    # create ksk
    ksks = keygen(zone, policy, "ns1/offline")
    assert len(ksks) == 2

    # check that 'dnssec-ksr keygen' pregenerates right amount of keys
    out, _ = ksr(zone, policy, "keygen", options="-K ns1 -i now -e +1y")
    zsks = out.split()
    # First algorithm keys have a lifetime of 3 months, so there should
    # be 4 created keys. Second algorithm keys have a lifetime of 5
    # months, so there should be 3 created keys.  While only two time
    # bundles of 5 months fit into one year, we need to create an extra
    # key for the remainder of the bundle. So 7 in total.
    assert len(zsks) == 7

    zsks_defalg = []
    zsks_altalg = []
    for zsk in zsks:
        alg = get_metadata(zsk, "Algorithm", keydir="ns1")
        if alg == os.environ.get("DEFAULT_ALGORITHM_NUMBER"):
            zsks_defalg.append(zsk)
        elif alg == os.environ.get("ALTERNATIVE_ALGORITHM_NUMBER"):
            zsks_altalg.append(zsk)

    assert len(zsks_defalg) == 4
    assert len(zsks_altalg) == 3

    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    size = os.environ.get("DEFAULT_BITS")
    lifetime = 8035200  # 3 months
    check_keys(zsks_defalg, lifetime, alg, size, keydir="ns1")

    alg = os.environ.get("ALTERNATIVE_ALGORITHM_NUMBER")
    size = os.environ.get("ALTERNATIVE_BITS")
    lifetime = 13392000  # 5 months
    check_keys(zsks_altalg, lifetime, alg, size, keydir="ns1")

    # check that 'dnssec-ksr request' creates correct ksr
    now = get_timing_metadata(zsks[0], "Created", keydir="ns1")
    until = addtime(now, 31536000)  # 1 year
    out, _ = ksr(zone, policy, "request", options=f"-K ns1 -i {now} -e +1y")

    fname = f"{zone}.ksr.{n}"
    with open(fname, "w", encoding="utf-8") as file:
        file.write(out)

    check_keysigningrequest(out, zsks, now, until, keydir="ns1")

    # check that 'dnssec-ksr sign' creates correct skr
    out, _ = ksr(
        zone, policy, "sign", options=f"-K ns1/offline -f {fname} -i {now} -e +1y"
    )

    skrfile = f"{zone}.skr.{n}"
    with open(skrfile, "w", encoding="utf-8") as file:
        file.write(out)

    refresh = -432000  # 5 days
    check_signedkeyresponse(
        out, zone, ksks, zsks, now, until, refresh, kskdir="ns1/offline", zskdir="ns1"
    )

    # add zone
    ns1 = servers["ns1"]
    ns1.rndc(
        f"addzone {zone} "
        + "{ type primary; file "
        + f'"{zone}.db"; dnssec-policy {policy}; '
        + "};",
        log=False,
    )

    # import skr
    shutil.copyfile(skrfile, f"ns1/{skrfile}")
    ns1.rndc(f"skr -import {skrfile} {zone}", log=False)

    # test zone is correctly signed
    # - check rndc dnssec -status output
    isctest.kasp.check_dnssecstatus(ns1, zone, zsks, policy=policy)
    # - zone is signed
    isctest.kasp.zone_is_signed(ns1, zone)
    # - dnssec_verify
    isctest.kasp.dnssec_verify(ns1, zone)
    # - check keys
    alg = os.environ.get("DEFAULT_ALGORITHM_NUMBER")
    size = os.environ.get("DEFAULT_BITS")
    lifetime = 8035200  # 3 months
    check_keys(zsks_defalg, lifetime, alg, size, keydir="ns1", with_state=True)

    alg = os.environ.get("ALTERNATIVE_ALGORITHM_NUMBER")
    size = os.environ.get("ALTERNATIVE_BITS")
    lifetime = 13392000  # 5 months
    check_keys(zsks_altalg, lifetime, alg, size, keydir="ns1", with_state=True)
    # - check apex
    isctest.kasp.check_apex(ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1")
    # - check subdomain
    isctest.kasp.check_subdomain(
        ns1, zone, ksks, zsks, kskdir="ns1/offline", zskdir="ns1"
    )
