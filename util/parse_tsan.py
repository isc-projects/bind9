#!/usr/bin/env python3
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

import sys, os, os.path, re
from hashlib import sha256

class State:
    inside = False
    block = ""
    last_line = None

    mutexes = {}
    m_index = 1
    threads = {}
    t_index = 1
    pointers = {}
    p_index = 1

    def init(self):
        self.reset()

    def reset(self):
        self.inside = False
        self.block = ""

        self.mutexes = {}
        self.threads = {}
        self.pointers = {}
        self.pointers["0x000000000000"] = 0

        self.m_index = 1
        self.t_index = 1
        self.p_index = 1

top = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

out = os.path.join(top, "tsan")

if not os.path.isdir(out):
    os.mkdir(out)

# Regular Expressions
mutex = re.compile(r"M\d+")
thread = re.compile(r"T\d+")
stack = re.compile(r"\s\(\S+\+0x\S+\)")
pointer = re.compile(r"0x[0-9a-f]+")
pid = re.compile(r"\(pid=\d+,?\)")
tid = re.compile(r"tid=\d+,?\s*")
worker = re.compile(r"\s+'(isc-worker|isc-net-)\d+'")
path = re.compile(top + "/")

s = State()


with open(sys.argv[1], "r", encoding='utf-8') as f:
    lines = f.readlines()
    for line in lines:
        if line == "==================\n":
           if not s.inside:
               s.inside = True
           else:
               dname = os.path.join(out, sha256(s.last_line.encode('utf-8')).hexdigest())
               if not os.path.isdir(dname):
                   os.mkdir(dname)
               fname = os.path.join(dname, sha256(s.block.encode('utf-8')).hexdigest() + ".tsan")
               if not os.path.isfile(fname):
                   with open(fname, "w", encoding='utf-8') as w:
                       w.write(s.block)
               s.reset()
        else:
            for m in mutex.finditer(line):
                k = m.group()
                if k not in s.mutexes:
                    s.mutexes[k] = s.m_index
                    s.m_index += 1
            for m in thread.finditer(line):
                k = m.group()
                if k not in s.threads:
                    s.threads[k] = s.t_index
                    s.t_index += 1
            for m in pointer.finditer(line):
                k = m.group()
                if k not in s.pointers:
                    s.pointers[k] = s.p_index
                    s.p_index += 1
            for k, v in s.mutexes.items():
                r = re.compile(k)
                line = r.sub("M%s" % v, line)
            for k, v in s.threads.items():
                r = re.compile(k)
                line = r.sub("T%s" % v, line)
            for k, v in s.pointers.items():
                r = re.compile(k)
                line = r.sub("0x%s" % str(v).zfill(12), line)

            line = stack.sub("", line)
            line = pid.sub("", line)
            line = tid.sub("", line)
            line = worker.sub("", line)
            line = path.sub("", line)

            s.block += line
            s.last_line = line
