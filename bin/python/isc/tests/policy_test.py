############################################################################
# Copyright (C) 2013-2015  Internet Systems Consortium, Inc. ("ISC")
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
import unittest
sys.path.append('../..')
from isc import *


class PolicyTest(unittest.TestCase):
    def test_keysize(self):
        pol = policy.dnssec_policy()
        pol.load('test-policies/01-keysize.pol')

        p = pol.policy('good_rsa.test', novalidate=True)
        self.assertEqual(p.get_name(), "good_rsa.test")
        self.assertEqual(p.constructed(), False)
        self.assertEqual(p.validate(), (True, ""))

        p = pol.policy('good_dsa.test', novalidate=True)
        self.assertEqual(p.get_name(), "good_dsa.test")
        self.assertEqual(p.constructed(), False)
        self.assertEqual(p.validate(), (True, ""))

        p = pol.policy('bad_dsa.test', novalidate=True)
        self.assertEqual(p.validate(),
                         (False, 'ZSK key size 769 not divisible by 64 as required for DSA'))

    def test_prepublish(self):
        pol = policy.dnssec_policy()
        pol.load('test-policies/02-prepublish.pol')
        p = pol.policy('good_prepublish.test', novalidate=True)
        self.assertEqual(p.validate(), (True, ""))

        p = pol.policy('bad_prepublish.test', novalidate=True)
        self.assertEqual(p.validate(),
                         (False, 'KSK pre/post-publish periods '
                                 '(10368000/5184000) combined exceed '
                                 'rollover period 10368000'))

    def test_postpublish(self):
        pol = policy.dnssec_policy()
        pol.load('test-policies/03-postpublish.pol')

        p = pol.policy('good_postpublish.test', novalidate=True)
        self.assertEqual(p.validate(), (True, ""))

        p = pol.policy('bad_postpublish.test', novalidate=True)
        self.assertEqual(p.validate(),
                         (False, 'KSK pre/post-publish periods '
                                 '(10368000/5184000) combined exceed '
                                 'rollover period 10368000'))

    def test_combined_pre_post(self):
        pol = policy.dnssec_policy()
        pol.load('test-policies/04-combined-pre-post.pol')

        p = pol.policy('good_combined_pre_post_ksk.test', novalidate=True)
        self.assertEqual(p.validate(), (True, ""))

        p = pol.policy('bad_combined_pre_post_ksk.test', novalidate=True)
        self.assertEqual(p.validate(),
                         (False, 'KSK pre/post-publish periods '
                                 '(5184000/5184000) combined exceed '
                                 'rollover period 10368000'))

        p = pol.policy('good_combined_pre_post_zsk.test', novalidate=True)
        self.assertEqual(p.validate(),
                         (True, ""))
        p = pol.policy('bad_combined_pre_post_zsk.test', novalidate=True)
        self.assertEqual(p.validate(),
                         (False, 'ZSK pre/post-publish periods '
                                 '(5184000/5184000) combined exceed '
                                 'rollover period 7776000'))

if __name__ == "__main__":
    unittest.main()
