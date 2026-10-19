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


from isctest.template import ANS3

from ..bailiwick_ans import ResponseSpoofer, a, cname, dname, ns, spoofing_server, txt

ATTACKER_IP = ANS3.ip


class UnsolicitedNsSpoofer(ResponseSpoofer, mode="unsolicited-ns"):
    qname = "trigger.victim."
    answer = [txt(qname, "spoofed answer with extra NS")]
    authority = [ns("victim.", "ns.attacker.")]
    authoritative = True


class ParentGlueSpoofer(ResponseSpoofer, mode="parent-glue"):
    qname = "trigger.victim."
    authority = [ns("trigger.victim.", "ns.victim.")]
    additional = [a("ns.victim.", ATTACKER_IP)]
    authoritative = False


class DnameSpoofer(ResponseSpoofer, mode="dname"):
    qname = "trigger.victim."
    answer = [
        cname(qname, "trigger.attacker."),
        dname("victim.", "attacker."),
    ]
    authoritative = True


def main() -> None:
    spoofing_server().run()


if __name__ == "__main__":
    main()
