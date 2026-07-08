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

import glob
import os
import subprocess

import dns.rcode
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(["conf/*.conf"])


def test_hooks():
    msg = isctest.query.create("example.com.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    # the test-async plugin changes the status of any positive answer to NOTIMP
    isctest.check.notimp(res)


def test_hooks_noextension(ns1, templates):
    templates.render("ns1/named.conf", {"noextension": True})
    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("reload")
        watcher.wait_for_line("all zones loaded")
    test_hooks()


def test_hooks_global_hook():
    msg = isctest.query.create("idontexists.example.com", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.rcode(res, dns.rcode.NOERROR)


def test_hooks_zone_hook1():
    msg = isctest.query.create("idonotexists.example2.com", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.rcode(res, dns.rcode.SERVFAIL)


def test_hooks_zone_hook2():
    msg = isctest.query.create("idonotexists.example3.com", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.rcode(res, dns.rcode.NOTIMP)


# ensure a plugin defined in a template is correcty registered to zone using
# this template
def test_hooks_zonetemplate1():
    msg = isctest.query.create("idonotexists.example4.com", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.rcode(res, dns.rcode.NOTAUTH)


# ensure plugin defined in zone are correctly registered when the zone also
# using a template with plugins (the plugin defined in the template is called
# first, but it bails out without doing anything because the first label is
# "skipfoo". So the plugin defined in the zone is then called, and return
# notzone)
def test_hooks_zonetemplate2():
    msg = isctest.query.create("skipfoo.example4.com", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.rcode(res, dns.rcode.NOTZONE)

    # test that the skip label is not matched add suffix
    msg = isctest.query.create("skipfooX.example4.com", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.rcode(res, dns.rcode.NOTAUTH)

    # test that the skip label is not matched add prefix
    msg = isctest.query.create("Xskipfoo.example4.com", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.rcode(res, dns.rcode.NOTAUTH)


def test_hooks_zone_rndc_reload(servers):
    ns2 = servers["ns2"]
    ns2.rndc("reload")


def test_hooks_checkconf():
    for filename in glob.glob("conf/good*.conf"):
        isctest.run.cmd([os.environ["CHECKCONF"], filename])
    for filename in glob.glob("conf/bad*.conf"):
        with pytest.raises(subprocess.CalledProcessError):
            isctest.run.cmd([os.environ["CHECKCONF"], filename])
