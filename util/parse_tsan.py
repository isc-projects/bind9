#!/usr/bin/env python3
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

"""Parse the ThreadSanizer reports, unify them and put them into unique dirs."""

import sys
import os
import os.path
import re
from hashlib import sha256


class State:
    """Class that holds state of the TSAN parser."""

    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-few-public-methods

    inside = False
    block = ""
    last_line = None

    mutexes = {}
    m_index = 1
    threads = {}
    t_index = 1
    pointers = {}
    p_index = 1

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset the object to initial state"""

        self.inside = False
        self.block = ""

        self.mutexes = {}
        self.threads = {}
        self.pointers = {}
        self.pointers["0x000000000000"] = 0

        self.m_index = 1
        self.t_index = 1
        self.p_index = 1


TOP = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

OUT = os.path.join(TOP, "tsan")

if not os.path.isdir(OUT):
    os.mkdir(OUT)

# Regular Expressions
MUTEX = re.compile(r"M\d+")
THREAD = re.compile(r"T\d+")
STACK = re.compile(r"\s\(\S+\+0x\S+\)")
POINTER = re.compile(r"0x[0-9a-f]+")
PID = re.compile(r"\(pid=\d+,?\)")
TID = re.compile(r"tid=\d+,?\s*")
WORKER = re.compile(r"\s+'(isc-worker|isc-net-)\d+'")
PATH = re.compile(TOP + "/")

S = State()

with open(sys.argv[1], "r", encoding='utf-8') as f:
    for line in f.readlines():
        if line == "==================\n":
            if not S.inside:
                S.inside = True
            else:
                DNAME = sha256(S.last_line.encode('utf-8')).hexdigest()
                DNAME = os.path.join(OUT, DNAME)
                if not os.path.isdir(DNAME):
                    os.mkdir(DNAME)
                FNAME = sha256(S.block.encode('utf-8')).hexdigest() + ".tsan"
                FNAME = os.path.join(DNAME, FNAME)
                if not os.path.isfile(FNAME):
                    with open(FNAME, "w", encoding='utf-8') as w:
                        w.write(S.block)
                S.reset()
        else:
            for m in MUTEX.finditer(line):
                k = m.group()
                if k not in S.mutexes:
                    S.mutexes[k] = S.m_index
                    S.m_index += 1
            for m in THREAD.finditer(line):
                k = m.group()
                if k not in S.threads:
                    S.threads[k] = S.t_index
                    S.t_index += 1
            for m in POINTER.finditer(line):
                k = m.group()
                if k not in S.pointers:
                    S.pointers[k] = S.p_index
                    S.p_index += 1
            for k, v in S.mutexes.items():
                r = re.compile(k)
                line = r.sub("M%s" % v, line)
            for k, v in S.threads.items():
                r = re.compile(k)
                line = r.sub("T%s" % v, line)
            for k, v in S.pointers.items():
                r = re.compile(k)
                line = r.sub("0x%s" % str(v).zfill(12), line)

            line = STACK.sub("", line)
            line = PID.sub("", line)
            line = TID.sub("", line)
            line = WORKER.sub("", line)
            line = PATH.sub("", line)

            S.block += line
            S.last_line = line
