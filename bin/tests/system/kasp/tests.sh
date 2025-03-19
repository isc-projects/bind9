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

set -e

# shellcheck source=conf.sh
. ../conf.sh
# shellcheck source=kasp.sh
. ../kasp.sh

start_time="$(TZ=UTC date +%s)"
status=0
n=0

###############################################################################
# Utilities                                                                   #
###############################################################################

# Call dig with default options.
dig_with_opts() {

  if [ -n "$TSIG" ]; then
    "$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" -y "$TSIG" "$@"
  else
    "$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" "$@"
  fi
}

# RNDC.
rndccmd() {
  "$RNDC" -c ../_common/rndc.conf -p "$CONTROLPORT" -s "$@"
}

# Log error and increment failure rate.
log_error() {
  echo_i "error: $1"
  ret=$((ret + 1))
}

# Default next key event threshold. May be extended by wait periods.
next_key_event_threshold=100

###############################################################################
# Tests                                                                       #
###############################################################################

#
# named
#

# The NSEC record at the apex of the zone and its RRSIG records are
# added as part of the last step in signing a zone.  We wait for the
# NSEC records to appear before proceeding with a counter to prevent
# infinite loops if there is an error.
n=$((n + 1))
echo_i "waiting for kasp signing changes to take effect ($n)"
ret=0

_wait_for_done_apexnsec() {
  while read -r zone; do
    dig_with_opts "$zone" @10.53.0.3 nsec >"dig.out.ns3.test$n.$zone" || return 1
    grep "NS SOA" "dig.out.ns3.test$n.$zone" >/dev/null || return 1
    grep "$zone\..*IN.*RRSIG" "dig.out.ns3.test$n.$zone" >/dev/null || return 1
  done <ns3/zones

  while read -r zone; do
    dig_with_opts "$zone" @10.53.0.6 nsec >"dig.out.ns6.test$n.$zone" || return 1
    grep "NS SOA" "dig.out.ns6.test$n.$zone" >/dev/null || return 1
    grep "$zone\..*IN.*RRSIG" "dig.out.ns6.test$n.$zone" >/dev/null || return 1
  done <ns6/zones

  return 0
}
retry_quiet 30 _wait_for_done_apexnsec || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
