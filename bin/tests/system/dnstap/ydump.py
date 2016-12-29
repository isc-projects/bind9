############################################################################
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
############################################################################

try:
    import yaml
except:
    print "I: No python yaml module, skipping"
    exit(1)

import subprocess
import pprint
import sys

DNSTAP_READ=sys.argv[1]
DATAFILE=sys.argv[2]

f = subprocess.Popen([DNSTAP_READ, '-y', DATAFILE], stdout=subprocess.PIPE)
pprint.pprint([l for l in yaml.load_all(f.stdout)])
