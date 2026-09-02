#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Fail the job if the kernel OOM killer ran during the tests.  Silent
# otherwise.
#
# A SIGKILLed process logs nothing, and start.pl detaches the servers it
# starts, so their exit status is lost too.  All that is left is a
# truncated named.run and "nsX died before a SIGTERM was sent", so ask
# the kernel instead.

set -eu

cgroup=/sys/fs/cgroup

# Fail runs that merely came close, too.  Every observed failure peaked at
# 97% of the limit - but so did runs that passed, one of them a megabyte
# above a run that was killed.  A result from that close is a coin toss,
# not a verdict on the code.
danger_percent=95

read_file() {
  cat "$1" 2>/dev/null || true
}

oom_kill_count() {
  awk '$1 == "oom_kill" { print $2 }'
}

# The kernel names what it killed here, when the buffer is readable at all
# - a container usually cannot read it.
oom_messages() {
  dmesg 2>/dev/null | grep -E "Killed process|was killed:" || true
}

# In a container the cgroup counter covers exactly our processes; a job
# that owns the whole machine has no such cgroup, and there the
# machine-wide counter is the same set.  FreeBSD has no counter, so count
# the kernel's messages.  The machine is fresh, so no baseline is needed.
where="on this machine"
if [ -r "$cgroup/memory.events" ]; then
  kills=$(read_file "$cgroup/memory.events" | oom_kill_count)
  where="in this container"
elif [ -r /proc/vmstat ]; then
  kills=$(read_file /proc/vmstat | oom_kill_count)
else
  kills=$(oom_messages | grep -c . || true)
fi

# Only a cgroup keeps a high water mark, so jobs outside a container get
# the kill check alone.
peak=$(read_file "$cgroup/memory.peak")
max=$(read_file "$cgroup/memory.max")

percent=
if [ -n "$peak" ] && [ "$max" -gt 0 ] 2>/dev/null; then
  percent=$((100 * peak / max))
fi

if [ "${kills:-0}" -gt 0 ]; then
  detail="${kills} process(es) ${where}"
  [ -z "$percent" ] || detail="${detail}, at a peak of ${percent}% of the limit"
  echo "E:OOM check: the kernel OOM killer killed ${detail};" \
    "a server reported as having 'died' was SIGKILLed, not crashed"
  oom_messages
  exit 1
fi

if [ -n "$percent" ] && [ "$percent" -ge "$danger_percent" ]; then
  echo "E:OOM check: peak memory use was ${percent}% of the container limit" \
    "(${peak} of ${max} bytes); at this level whether a run survives is a" \
    "coin toss - runs have both passed and been OOM killed within a" \
    "megabyte of this peak - so this result cannot be trusted"
  exit 1
fi
