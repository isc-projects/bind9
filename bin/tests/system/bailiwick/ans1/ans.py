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

from ..bailiwick_ans import ResponseSpoofer, a, ns, spoofing_server, txt

ATTACKER_IP = ANS3.ip


class SiblingNsSpoofer(ResponseSpoofer, mode="sibling-ns"):
    qname = "trigger."
    answer = [txt(qname, "spoofed answer with extra NS")]
    authority = [ns("victim.", "ns.attacker.")]
    additional = [a("ns.attacker.", ATTACKER_IP)]
    authoritative = True


def main() -> None:
    spoofing_server().run()


if __name__ == "__main__":
    main()
