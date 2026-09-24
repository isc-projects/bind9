# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

from pathlib import Path
from string import ascii_lowercase

import isctest


def qname(n):
    return f"q{n:02}.l2.l1.l0"


def write_case(
    templates, case_id, n_queries, zones, qname_wait_recurse=False, serial=1
):
    """
    Write ns2's config, query list and policy zones for one test case.

    zones lists the policy zones in response-policy order, each as the
    list of triggers it contains: a trigger type known to
    ns2/policy.db.j2.manual, or the number of the query that a qname
    trigger matches.
    """
    names = [f"{case_id}.{i:02}.policy.local" for i in range(len(zones))]

    queries = [f"{qname(n)}\n" for n in range(1, n_queries + 1)]
    Path(f"ns2/{case_id}.queries").write_text("".join(queries), encoding="utf-8")

    templates.render(
        f"ns2/named.{case_id}.conf",
        {"policy_zones": names, "qname_wait_recurse": qname_wait_recurse},
        template="ns2/named.case.conf.j2.manual",
    )

    for name, triggers in zip(names, zones):
        triggers = [qname(t) if isinstance(t, int) else t for t in triggers]
        templates.render(
            f"ns2/db.{name}",
            {"serial": serial, "triggers": triggers},
            template="ns2/policy.db.j2.manual",
        )


def bootstrap():
    templates = isctest.template.TemplateEngine(".")

    # Group 1: one policy zone with recursion-skipping triggers only
    write_case(templates, "1a", 1, [["client-ip"]])
    write_case(templates, "1b", 2, [[1]])
    write_case(templates, "1c", 1, [["client-ip", 2]])

    # Group 2: 32 such zones with one qname trigger each
    write_case(templates, "2a", 33, [[q] for q in range(1, 33)])

    # Group 3: triggers that need recursion, alone and next to a qname one
    write_case(templates, "3a", 1, [["ip"]])
    write_case(templates, "3b", 1, [["nsdname"]])
    write_case(templates, "3c", 1, [["nsip"]])
    write_case(templates, "3d", 2, [["ip", 1]])
    write_case(templates, "3e", 2, [["nsdname", 1]])
    write_case(templates, "3f", 2, [["nsip", 1]])

    # Group 4 (4aa to 4bf): 32 qname-trigger zones, with an "ip" trigger
    # added to the zone at position n so that n+1 of the 33 queries skip
    # recursion
    for n in range(32):
        case_id = f"4{ascii_lowercase[n // 26]}{ascii_lowercase[n % 26]}"
        zones = [[q] for q in range(1, n + 1)]
        zones += [["ip", n + 2]]
        zones += [[q + 2] for q in range(n + 1, 32)]
        write_case(templates, case_id, 33, zones)

    # Group 5: the first zone with a recursion-requiring trigger is the pivot
    write_case(templates, "5a", 6, [[1], [2, "ip"], [4], [5, "ip"], [6]])

    # Group 6: policy update races; tests.sh copies 6b's and 6c's zone file
    # over 6a's and reloads it, so their serials must increase
    write_case(templates, "6a", 0, [[]], qname_wait_recurse=True)
    write_case(templates, "6b", 0, [["nsdname"]], qname_wait_recurse=True, serial=2)
    write_case(templates, "6c", 0, [[]], qname_wait_recurse=True, serial=3)
