############################################################################
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
############################################################################

import sys
sys.path.insert(0, '../../../python')
from isc import *

pp = policy.dnssec_policy()
# print the unmodified default and a generated zone policy
print(pp.named_policy['default'])
print(pp.named_policy['global'])
print(pp.policy('example.com'))

if len(sys.argv) > 0:
    for policy_file in sys.argv[1:]:
        pp.load(policy_file)

        # now print the modified default and generated zone policies
        print(pp.named_policy['default'])
        print(pp.policy('example.com'))
        print(pp.policy('example.org'))
        print(pp.policy('example.net'))

        # print algorithm policies
        print(pp.alg_policy['RSASHA1'])
        print(pp.alg_policy['DSA'])

        # print another named policy
        print(pp.named_policy['extra'])
else:
    print("ERROR: Please provide an input file")
