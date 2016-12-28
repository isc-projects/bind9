#!/usr/bin/python

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
