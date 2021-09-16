#!/usr/bin/python3
############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

import os
import pytest
import dns.resolver


# @pytest.mark.dnspython
def test_rpz_passthru_logging(named_port):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['10.53.0.1']
    resolver.port = named_port

    # Should generate a log entry into rpz_passthru.txt
    ans = resolver.query('allowed.', 'A')
    for rd in ans:
        assert rd.address == "10.53.0.2"

    # baddomain.com isn't allowed (CNAME .), should return NXDOMAIN
    # Should generate a log entry into rpz.txt
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.query('baddomain.', 'A')

    rpz_passthru_logfile = os.path.join("ns1", "rpz_passthru.txt")
    rpz_logfile = os.path.join("ns1", "rpz.txt")

    assert os.path.isfile(rpz_passthru_logfile)
    assert os.path.isfile(rpz_logfile)

    with open(rpz_passthru_logfile, encoding='utf-8') as log_file:
        line = log_file.read()
        assert "rpz QNAME PASSTHRU rewrite allowed/A/IN" in line

    with open(rpz_logfile, encoding='utf-8') as log_file:
        line = log_file.read()
        assert "rpz QNAME PASSTHRU rewrite allowed/A/IN" not in line
        assert "rpz QNAME NXDOMAIN rewrite baddomain/A/IN" in line
