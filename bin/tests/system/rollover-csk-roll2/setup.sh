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
# The zones at csk-roll2.autosign represent the various steps of a CSK rollover
# (which is essentially a ZSK Pre-Publication / KSK Double-KSK rollover).
# This scenario differs from the csk-roll1 one because the zone signatures (ZRRSIG)
# are replaced with the new key sooner than the DS is swapped.
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.csk-roll2.autosign
TactN="now-7d"
keytimes="-P ${TactN} -A ${TactN}"
CSK=$($KEYGEN -k csk-roll2 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN -z $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-256,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 2:
# It is time to introduce the new CSK.
setup step2.csk-roll2.autosign
# According to RFC 7583:
# KSK: Tpub(N+1) <= Tact(N) + Lksk - IpubC
# ZSK: Tpub(N+1) <= Tact(N) + Lzsk - Ipub
# IpubC = DprpC + TTLkey (+publish-safety)
# Ipub  = IpubC
# Lcsk = Lksk = Lzsk
#
# Lcsk:           6mo (186d, 4464h)
# Dreg:           N/A
# DprpC:          1h
# TTLkey:         1h
# publish-safety: 1h
# Ipub:           3h
#
# Tact(N)  = now - Lcsk + Ipub = now - 186d + 3h
#          = now - 4464h + 3h = now - 4461h
TactN="now-4461h"
keytimes="-P ${TactN} -A ${TactN}"
CSK=$($KEYGEN -k csk-roll2 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN -z $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-256,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 3:
# It is time to submit the DS and to roll signatures.
setup step3.csk-roll2.autosign
# According to RFC 7583:
#
# Tsbm(N+1) >= Trdy(N+1)
# KSK: Tact(N+1) = Tsbm(N+1)
# ZSK: Tact(N+1) = Tpub(N+1) + Ipub = Tsbm(N+1)
# KSK: Iret  = DprpP + TTLds (+retire-safety)
# ZSK: IretZ = Dsgn + Dprp + TTLsig (+retire-safety)
#
# Lcsk:           186d
# Dprp:           1h
# DprpP:          1w
# Dreg:           N/A
# Dsgn:           12h
# TTLds:          1h
# TTLsig:         1d
# retire-safety:  1h
# Iret:           170h
# IretZ:          38h
# Ipub:           3h
#
# Tpub(N)   = now - Lcsk = now - 186d
# Tact(N)   = now - Lcsk + Dprp + TTLsig = now - 4439h
# Tret(N)   = now
# Trem(N)   = now + Iret = now + 170h
# Tpub(N+1) = now - Ipub = now - 3h
# Tact(N+1) = Tret(N)
# Tret(N+1) = now + Lcsk = now + 186d
# Trem(N+1) = now + Lcsk + Iret = now + 186d + 170h =
#           = now + 4464h + 170h = now + 4634h
TpubN="now-186d"
TactN="now-4439h"
TretN="now"
TremN="now+170h"
TpubN1="now-3h"
TactN1="${TretN}"
TretN1="now+186d"
TremN1="now+4634h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll2 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll2 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $O $TactN -z $O $TactN "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -r $R $TpubN1 -d $H $TpubN1 -z $H $TpubN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-256,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 4:
# Some time later all the ZRRSIG records should be from the new CSK, and the
# DS should be swapped.  The ZRRSIG records are all replaced after IretZ (38h).
# The DS is swapped after Dreg + Iret (1w3h). In other words, the zone
# signatures are replaced before the DS is swapped.
setup step4.csk-roll2.autosign
# According to RFC 7583:
# Trem(N)    = Tret(N) + IretZ
#
# Lcsk:   186d
# Dreg:   N/A
# Iret:   170h
# IretZ:  38h
#
# Tpub(N)    = now - IretZ - Lcsk = now - 38h - 186d
#            = now - 38h - 4464h = now - 4502h
# Tact(N)    = now - Iret - Lcsk + TTLsig = now - 4502h + 25h = now - 4477h
# Tret(N)    = now - IretZ = now - 38h
# Trem(N)    = now - IretZ + Iret = now - 38h + 170h = now + 132h
# Tpub(N+1)  = now - IretZ - IpubC = now - 38h - 3h = now - 41h
# Tact(N+1)  = Tret(N)
# Tret(N+1)  = now - IretZ + Lcsk = now - 38h + 186d
#            = now + 4426h
# Trem(N+1)  = now - IretZ + Lcsk + Iret
#            = now + 4426h + 3h = now + 4429h
TpubN="now-4502h"
TactN="now-4477h"
TretN="now-38h"
TremN="now+132h"
TpubN1="now-41h"
TactN1="${TretN}"
TretN1="now+4426h"
TremN1="now+4429h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll2 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll2 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -z $U $TretN -d $U $TactN1 -D ds $TactN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -z $R $TactN1 -d $R $TactN1 -P ds $TactN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-256,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 5:
# Some time later the DS can be swapped and the old DNSKEY can be removed from
# the zone.
setup step5.csk-roll2.autosign
# Subtract Iret (170h) - IretZ (38h) = 132h.
#
# Tpub(N)   = now - 4502h - 132h = now - 4634h
# Tact(N)   = now - 4477h - 132h = now - 4609h
# Tret(N)   = now - 38h - 132h = now - 170h
# Trem(N)   = now + 132h - 132h = now
# Tpub(N+1) = now - 41h - 132h = now - 173h
# Tact(N+1) = Tret(N)
# Tret(N+1) = now + 4426h - 132h = now + 4294h
# Trem(N+1) = now + 4492h - 132h = now + 4360h
TpubN="now-4634h"
TactN="now-4609h"
TretN="now-170h"
TremN="now"
TpubN1="now-173h"
TactN1="${TretN}"
TretN1="now+4294h"
TremN1="now+4360h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll2 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll2 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -z $H now-133h -d $U $TactN1 -D ds $TactN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -z $O now-133h -d $R $TactN1 -P ds $TactN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-256,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 6:
# Some time later the predecessor DNSKEY enters the HIDDEN state.
setup step6.csk-roll2.autosign
# Subtract DNSKEY TTL plus zone propagation delay (2h).
#
# Tpub(N)   = now - 4634h - 2h = now - 4636h
# Tact(N)   = now - 4609h - 2h = now - 4611h
# Tret(N)   = now - 170h - 2h = now - 172h
# Trem(N)   = now - 2h
# Tpub(N+1) = now - 173h - 2h = now - 175h
# Tact(N+1) = Tret(N)
# Tret(N+1) = now + 4294h - 2h = now + 4292h
# Trem(N+1) = now + 4360h - 2h = now + 4358h
TpubN="now-4636h"
TactN="now-4611h"
TretN="now-172h"
TremN="now-2h"
TpubN1="now-175h"
TactN1="${TretN}"
TretN1="now+4292h"
TremN1="now+4358h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll2 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll2 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $U $TremN -r $U $TremN -d $H $TremN -z $H now-135h "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TremN -z $O now-135h "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-256,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 7:
# The predecessor DNSKEY can be purged, but purge-keys is disabled.
setup step7.csk-roll2.autosign
# Subtract 90 days (default, 2160h) from all the times.
#
# Tpub(N)   = now - 4636h - 2160h = now - 6796h
# Tact(N)   = now - 4611h - 2160h = now - 6771h
# Tret(N)   = now - 172h - 2160h = now - 2332h
# Trem(N)   = now - 2h - 2160h = now - 2162h
# Tpub(N+1) = now - 175h - 2160h = now - 2335h
# Tact(N+1) = Tret(N)
# Tret(N+1) = now + 4292h - 2160h = now + 2132h
# Trem(N+1) = now + 4358h - 2160h = now + 2198h
TpubN="now-6796h"
TactN="now-6771h"
TretN="now-2332h"
TremN="now-2162h"
TpubN1="now-2335h"
TactN1="${TretN}"
TretN1="now+2132h"
TremN1="now+2198h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll2 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll2 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $U $TremN -r $U $TremN -d $H $TremN -z $H now-135h "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TremN -z $O now-135h "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-256,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
