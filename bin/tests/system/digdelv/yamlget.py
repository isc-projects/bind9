############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

try:
    import yaml
except:
    print("No python yaml module, skipping")
    exit(1)

import subprocess
import pprint
import sys

f = open(sys.argv[1], "r")
for item in yaml.safe_load_all(f):
    for key in sys.argv[2:]:
        try:
            key = int(key)
        except: pass
        try:
            item = item[key]
        except:
            print('error: index not found')
            exit(1)
    print (item)
