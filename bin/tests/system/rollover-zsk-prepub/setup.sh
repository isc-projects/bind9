#!/bin/sh -e

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

# shellcheck source=conf.sh
. ../conf.sh

cd "ns3"

setup() {
  zone="$1"
  echo_i "setting up zone: $zone"
  zonefile="${zone}.db"
  infile="${zone}.db.infile"
  echo "$zone" >>zones
}

# Set in the key state files the Predecessor/Successor fields.
# Key $1 is the predecessor of key $2.
key_successor() {
  id1=$(keyfile_to_key_id "$1")
  id2=$(keyfile_to_key_id "$2")
  echo "Predecessor: ${id1}" >>"${2}.state"
  echo "Successor: ${id2}" >>"${1}.state"
}

# Make lines shorter by storing key states in environment variables.
H="HIDDEN"
R="RUMOURED"
O="OMNIPRESENT"
U="UNRETENTIVE"

#
# The zones at zsk-prepub.autosign represent the various steps of a ZSK
# Pre-Publication rollover.
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.zsk-prepub.autosign
TactN="now-7d"
keytimes="-P ${TactN} -A ${TactN}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 2:
# It is time to pre-publish the successor ZSK.
setup step2.zsk-prepub.autosign
# According to RFC 7583:
# Tact(N) = now + Ipub - Lzsk = now + 26h - 30d
#         = now + 26h - 30d = now − 694h
TactN="now-694h"
keytimes="-P ${TactN} -A ${TactN}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 3:
# After the publication interval has passed the DNSKEY of the successor ZSK
# is OMNIPRESENT and the zone can thus be signed with the successor ZSK.
setup step3.zsk-prepub.autosign
# According to RFC 7583:
# Tpub(N+1) <= Tact(N) + Lzsk - Ipub
# Tact(N+1) = Tact(N) + Lzsk
#
# Tact(N)   = now - Lzsk = now - 30d
# Tpub(N+1) = now - Ipub = now - 26h
# Tact(N+1) = now
# Tret(N) = now
# Trem(N) = now + Iret = now + Dsign + Dprp + TTLsig + retire-safety = 8d1h = now + 241h
TactN="now-30d"
TpubN1="now-26h"
TactN1="now"
TremN="now+241h"
keytimes="-P ${TactN}  -A ${TactN}"
oldtimes="-P ${TactN}  -A ${TactN} -I ${TactN1} -D ${TremN}"
newtimes="-P ${TpubN1} -A ${TactN1}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $oldtimes $zone 2>keygen.out.$zone.2)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $newtimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $O $TactN -z $O $TactN "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -z $H $TpubN1 "$ZSK2" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $ZSK1 $ZSK2
# Sign zone.
cat template.db.in "${KSK}.key" "${ZSK1}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 4:
# After the retire interval has passed the predecessor DNSKEY can be
# removed from the zone.
setup step4.zsk-prepub.autosign
# Lzsk:          30d
# Ipub:          26h
# Dsgn:          1w
# Dprp:          1h
# TTLsig:        1d
# retire-safety: 2d
#
# According to RFC 7583:
# Iret      = Dsgn + Dprp + TTLsig (+retire-safety)
# Iret      = 1w + 1h + 1d + 2d = 10d1h = 241h
#
# Tact(N)   = now - Iret - Lzsk
#           = now - 241h - 30d = now - 241h - 720h
#           = now - 961h
# Tpub(N+1) = now - Iret - Ipub
#           = now - 241h - 26h
#           = now - 267h
# Tact(N+1) = now - Iret = now - 241h
TactN="now-961h"
TpubN1="now-267h"
TactN1="now-241h"
TremN="now"
keytimes="-P ${TactN}  -A ${TactN}"
oldtimes="-P ${TactN}  -A ${TactN} -I ${TactN1} -D ${TremN}"
newtimes="-P ${TpubN1} -A ${TactN1}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $oldtimes $zone 2>keygen.out.$zone.2)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $newtimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $O $TactN -z $U $TactN1 "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TactN1 -z $R $TactN1 "$ZSK2" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $ZSK1 $ZSK2
# Sign zone.
cat template.db.in "${KSK}.key" "${ZSK1}.key" "${ZSK2}.key" >"$infile"
cp $infile $zonefile
$SIGNER -PS -x -s now-2w -e now-1mi -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 5:
# The predecessor DNSKEY is removed long enough that is has become HIDDEN.
setup step5.zsk-prepub.autosign
# Subtract DNSKEY TTL + zone-propagation-delay from all the times (2h).
# Tact(N)   = now - 961h - 2h = now - 963h
# Tpub(N+1) = now - 267h - 2h = now - 269h
# Tact(N+1) = now - 241h - 2h = now - 243h
# Trem(N)   = Tact(N+1) + Iret = now -2h
TactN="now-963h"
TremN="now-2h"
TpubN1="now-269h"
TactN1="now-243h"
TremN="now-2h"
keytimes="-P ${TactN}  -A ${TactN}"
oldtimes="-P ${TactN}  -A ${TactN} -I ${TactN1} -D ${TremN}"
newtimes="-P ${TpubN1} -A ${TactN1}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $oldtimes $zone 2>keygen.out.$zone.2)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $newtimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $U $TremN -z $H $TremN "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TactN1 -z $O $TremN "$ZSK2" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $ZSK1 $ZSK2
# Sign zone.
cat template.db.in "${KSK}.key" "${ZSK1}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 6:
# The predecessor DNSKEY can be purged.
setup step6.zsk-prepub.autosign
# Subtract purge-keys interval from all the times (1h).
TactN="now-964h"
TremN="now-3h"
TpubN1="now-270h"
TactN1="now-244h"
TremN="now-3h"
keytimes="-P ${TactN}  -A ${TactN}"
oldtimes="-P ${TactN}  -A ${TactN} -I ${TactN1} -D ${TremN}"
newtimes="-P ${TpubN1} -A ${TactN1}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $oldtimes $zone 2>keygen.out.$zone.2)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $newtimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $H $TremN -z $H $TremN "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TactN1 -z $O $TremN "$ZSK2" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $ZSK1 $ZSK2
# Sign zone.
cat template.db.in "${KSK}.key" "${ZSK1}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
