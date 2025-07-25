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
import re
import time

import isctest


# helper functions
def hasmatch(regex, blob):
    return re.search(regex, blob, flags=re.MULTILINE)


def active(blob):
    return len([x for x in blob.splitlines() if " expiry" in x])


# global start-time variable
# pylint: disable=global-statement
# pylint: disable=global-variable-not-assigned
start = 0


def test_initial():
    m = isctest.query.create("a.bogus.example.", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.servfail(res)

    m = isctest.query.create("badds.example.", "SOA")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.servfail(res)

    m = isctest.query.create("a.secure.example.", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)


def test_nta_validate_except(servers):
    ns4 = servers["ns4"]
    response = ns4.rndc("secroots -", log=False)
    assert hasmatch("^corp: permanent", response)

    # check insecure local domain works with validate-except
    m = isctest.query.create("www.corp", "NS")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)


def test_nta_bogus_lifetimes(servers):
    ns4 = servers["ns4"]

    # no nta lifetime specified:
    response = ns4.rndc("nta -l '' foo", ignore_errors=True, log=False)
    assert "'nta' failed: bad ttl" in response

    # bad nta lifetime:
    response = ns4.rndc("nta -l garbage foo", ignore_errors=True, log=False)
    assert "'nta' failed: bad ttl" in response

    # excessive nta lifetime:
    response = ns4.rndc("nta -l 7d1h foo", ignore_errors=True, log=False)
    assert "'nta' failed: out of range" in response


def test_nta_install(servers):
    global start

    ns4 = servers["ns4"]
    ns4.rndc("nta -f -l 20s bogus.example", log=False)
    ns4.rndc("nta badds.example", log=False)

    # NTAs should persist after reconfig
    with ns4.watch_log_from_here() as watcher:
        ns4.reconfigure(log=False)
        watcher.wait_for_line("any newly configured zones are now loaded")

    response = ns4.rndc("nta -d", log=False)
    assert len(response.splitlines()) == 3

    ns4.rndc("nta secure.example", log=False)
    ns4.rndc("nta fakenode.secure.example", log=False)
    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("reload", log=False)
        watcher.wait_for_line("all zones loaded")

    response = ns4.rndc("nta -d", log=False)
    assert len(response.splitlines()) == 5

    start = time.time()


def test_nta_behavior(servers):
    global start
    assert start, "test_nta_behavior must be run as part of the full NTA test"

    m = isctest.query.create("a.bogus.example.", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    m = isctest.query.create("badds.example.", "SOA")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    m = isctest.query.create("a.secure.example.", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    m = isctest.query.create("a.fakenode.secure.example.", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noadflag(res)

    ns4 = servers["ns4"]
    response = ns4.rndc("secroots -", log=False)
    assert hasmatch("^bogus.example: expiry", response)
    assert hasmatch("^badds.example: expiry", response)
    assert hasmatch("^secure.example: expiry", response)
    assert hasmatch("^fakenode.secure.example: expiry", response)

    # secure.example and badds.example used the default nta-duration
    # (configured as 12s in ns4/named1.conf), but the nta recheck interval
    # is configured to 9s, so at t=10 the NTAs for secure.example and
    # fakenode.secure.example should both be lifted, while badds.example
    # should still be going.
    delay = start + 10 - time.time()
    if delay > 0:
        time.sleep(delay)

    m = isctest.query.create("b.secure.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    m = isctest.query.create("b.fakenode.secure.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.nxdomain(res)
    isctest.check.adflag(res)

    m = isctest.query.create("badds.example.", "SOA")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    # bogus.example was set to expire in 20s, so at t=13
    # it should still be NTA'd, but badds.example used the default
    # lifetime of 12s, so it should revert to SERVFAIL now.
    delay = start + 13 - time.time()
    if delay > 0:
        time.sleep(delay)

    response = ns4.rndc("nta -d", log=False)
    assert active(response) <= 2

    response = ns4.rndc("secroots -", log=False)
    assert hasmatch("bogus.example: expiry", response)
    assert not hasmatch("badds.example: expiry", response)

    m = isctest.query.create("b.bogus.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)

    m = isctest.query.create("a.badds.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.servfail(res)
    isctest.check.noadflag(res)

    m = isctest.query.create("c.secure.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # at t=21, all the NTAs should have expired.
    delay = start + 21 - time.time()
    if delay > 0:
        time.sleep(delay)

    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 0

    m = isctest.query.create("d.secure.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    m = isctest.query.create("c.bogus.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.servfail(res)
    isctest.check.noadflag(res)


def test_nta_removals(servers):
    ns4 = servers["ns4"]
    ns4.rndc("nta badds.example", log=False)

    response = ns4.rndc("nta -d", log=False)
    assert hasmatch("^badds.example/_default: expiry", response)

    m = isctest.query.create("a.badds.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    response = ns4.rndc("nta -remove badds.example", log=False)
    assert "Negative trust anchor removed: badds.example" in response

    response = ns4.rndc("nta -d", log=False)
    assert not hasmatch("^badds.example/_default: expiry", response)

    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.servfail(res)
    isctest.check.noadflag(res)

    # remove non-existent NTA three times
    ns4.rndc("nta -r foo", log=False)
    ns4.rndc("nta -remove foo", log=False)
    response = ns4.rndc("nta -r foo", log=False)
    assert "not found" in response


def test_nta_restarts(servers):
    global start
    assert start, "test_nta_restarts must be run as part of the full NTA test"

    # test NTA persistence across restarts
    ns4 = servers["ns4"]
    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 0

    start = time.time()
    ns4.rndc("nta -f -l 30s bogus.example", log=False)
    ns4.rndc("nta -f -l 10s badds.example", log=False)
    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 2

    # stop the server
    ns4.stop()

    # wait 14s before restarting. badds.example's NTA (lifetime=10s) should
    # have expired, and bogus.example should still be running.
    delay = start + 14 - time.time()
    if delay > 0:
        time.sleep(delay)
    ns4.start(["--noclean", "--restart", "--port", os.environ["PORT"]])

    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 1
    assert hasmatch("^bogus.example/_default: expiry", response)

    m = isctest.query.create("a.badds.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.servfail(res)

    m = isctest.query.create("a.bogus.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    ns4.rndc("nta -r bogus.example", log=False)


def test_nta_regular(servers):
    global start
    assert start, "test_nta_regular must be run as part of the full NTA test"

    # check "regular" attribute in NTA file
    ns4 = servers["ns4"]

    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 0

    # secure.example validates with AD=1
    m = isctest.query.create("a.secure.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # stop the server, update _default.nta, restart
    ns4.stop()
    now = time.localtime()
    future = str(now.tm_year + 20) + "0101010000"
    with open("ns4/_default.nta", "w", encoding="utf-8") as f:
        f.write(f"secure.example. regular {future}")

    ns4.start(["--noclean", "--restart", "--port", os.environ["PORT"]])

    # NTA active; secure.example. should now return an AD=0 answer.
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    # nta-recheck is configured as 9s, so at t=12 the NTA for
    # secure.example. should be lifted as it is not a "forced" NTA.
    start = time.mktime(now)
    delay = start + 12 - time.time()
    if delay > 0:
        time.sleep(delay)

    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 0

    # NTA lifted; secure.example. flush the cache to trigger a new query,
    # and it should now return an AD=1 answer.
    ns4.rndc("flushtree secure.example", log=False)
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)


def test_nta_forced(servers):
    global start
    assert start, "test_nta_regular must be run as part of the full NTA test"

    # check "forced" attribute in NTA file
    ns4 = servers["ns4"]

    # just to be certain, clean up any existing NTA first
    ns4.rndc("nta -r secure.example", log=False)

    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 0

    # secure.example validates with AD=1
    m = isctest.query.create("a.secure.example", "A")
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # stop the server, update _default.nta, restart
    ns4.stop()
    now = time.localtime()
    future = str(now.tm_year + 20) + "0101010000"
    with open("ns4/_default.nta", "w", encoding="utf-8") as f:
        f.write(f"secure.example. forced {future}")

    ns4.start(["--noclean", "--restart", "--port", os.environ["PORT"]])

    # NTA active; secure.example. should now return an AD=0 answer
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    # nta-recheck is configured as 9s. at t=12 the NTA for
    # secure.example. should NOT be lifted as it is "forced".
    start = time.mktime(now)
    delay = start + 12 - time.time()
    if delay > 0:
        time.sleep(delay)

    # NTA lifted; secure.example. should still return an AD=0 answer
    ns4.rndc("flushtree secure.example", log=False)
    res = isctest.query.tcp(m, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)


def test_nta_clamping(servers):
    ns4 = servers["ns4"]

    # clean up any existing NTA
    ns4.rndc("nta -r secure.example", log=False)

    # stop the server, update _default.nta, restart
    ns4.stop()
    now = time.localtime()
    future = str(now.tm_year + 20) + "0101010000"
    with open("ns4/_default.nta", "w", encoding="utf-8") as f:
        f.write(f"secure.example. forced {future}")

    ns4.start(["--noclean", "--restart", "--port", os.environ["PORT"]])

    # check that NTA lifetime read from file is clamped to 1 week.
    response = ns4.rndc("nta -d", log=False)
    assert active(response) == 1

    nta = next((s for s in response.splitlines() if " expiry" in s), None)
    assert nta is not None

    nta = nta.split(" ")
    expiry = f"{nta[2]} {nta[3]}"
    then = time.mktime(time.strptime(expiry, "%d-%b-%Y %H:%M:%S.000"))
    nextweek = time.mktime(now) + (86400 * 7)

    # normally there's no more than a few seconds difference between the
    # clamped expiration date and the calculated date for next week,
    # but add a 3600 second fudge factor to allow for daylight savings
    # changes.
    assert abs(nextweek - then < 3610)

    # remove the NTA
    ns4.rndc("nta -r secure.example", log=False)


def test_nta_forward(servers):
    ns9 = servers["ns9"]

    m = isctest.query.create("badds.example", "SOA")
    res = isctest.query.tcp(m, "10.53.0.9")
    isctest.check.servfail(res)
    isctest.check.empty_answer(res)
    isctest.check.noadflag(res)

    # add NTA and expect resolution to succeed
    ns9.rndc("nta badds.example", log=False)
    res = isctest.query.tcp(m, "10.53.0.9")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 2)
    isctest.check.noadflag(res)

    # remove NTA and expect resolution to fail again
    ns9.rndc("nta -remove badds.example", log=False)
    res = isctest.query.tcp(m, "10.53.0.9")
    isctest.check.servfail(res)
    isctest.check.empty_answer(res)
    isctest.check.noadflag(res)
