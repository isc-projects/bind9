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
# The zones at csk-roll1.autosign represent the various steps of a CSK rollover
# (which is essentially a ZSK Pre-Publication / KSK Double-KSK rollover).
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.csk-roll1.autosign
TactN="now-7d"
keytimes="-P ${TactN} -A ${TactN}"
CSK=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN -z $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 2:
# It is time to introduce the new CSK.
setup step2.csk-roll1.autosign
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
# Tact(N) = now - Lcsk + Ipub = now - 186d + 3h
#         = now - 4464h + 3h  = now - 4461h
TactN="now-4461h"
keytimes="-P ${TactN} -A ${TactN}"
CSK=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN -z $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 3:
# It is time to submit the DS and to roll signatures.
setup step3.csk-roll1.autosign
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
# DprpP:          1h
# Dreg:           N/A
# Dsgn:           25d
# TTLds:          1h
# TTLsig:         1d
# retire-safety:  2h
# Iret:           4h
# IretZ:          26d3h
# Ipub:           3h
#
# Tpub(N)   = now - Lcsk = now - 186d
# Tact(N)   = now - Lcsk + Dprp + TTLsig = now - 4439h
# Tret(N)   = now
# Trem(N)   = now + IretZ = now + 26d3h = now + 627h
# Tpub(N+1) = now - Ipub = now - 3h
# Tact(N+1) = Tret(N)
# Tret(N+1) = now + Lcsk = now + 186d = now + 186d
# Trem(N+1) = now + Lcsk + IretZ = now + 186d + 26d3h =
#           = now + 5091h
TpubN="now-186d"
TactN="now-4439h"
TretN="now"
TremN="now+627h"
TpubN1="now-3h"
TactN1="${TretN}"
TretN1="now+186d"
TremN1="now+5091h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll1 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $O $TactN -z $O $TactN "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -r $R $TpubN1 -d $H $TpubN1 -z $H $TpubN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 4:
# Some time later all the ZRRSIG records should be from the new CSK, and the
# DS should be swapped.  The ZRRSIG records are all replaced after IretZ
# (which is 26d3h).  The DS is swapped after Iret (which is 4h).
# In other words, the DS is swapped before all zone signatures are replaced.
setup step4.csk-roll1.autosign
# According to RFC 7583:
# Trem(N)    = Tret(N) - Iret + IretZ
# now       = Tsbm(N+1) + Iret
#
# Lcsk:   186d
# Iret:   4h
# IretZ:  26d3h
#
# Tpub(N)   = now - Iret - Lcsk = now - 4h - 186d = now - 4468h
# Tret(N)   = now - Iret = now - 4h = now - 4h
# Trem(N)   = now - Iret + IretZ = now - 4h + 26d3h
#           = now + 623h
# Tpub(N+1) = now - Iret - IpubC = now - 4h - 3h = now - 7h
# Tact(N+1) = Tret(N)
# Tret(N+1) = now - Iret + Lcsk = now - 4h + 186d = now + 4460h
# Trem(N+1) = now - Iret + Lcsk + IretZ = now - 4h + 186d + 26d3h
#           = now + 5087h
TpubN="now-4468h"
TactN="now-4443h"
TretN="now-4h"
TremN="now+623h"
TpubN1="now-7h"
TactN1="${TretN}"
TretN1="now+4460h"
TremN1="now+5087h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll1 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $U $TactN1 -z $U $TactN1 -D ds $TactN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $R $TactN1 -z $R $TactN1 -P ds $TactN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 5:
# After the DS is swapped in step 4, also the KRRSIG records can be removed.
# At this time these have all become hidden.
setup step5.csk-roll1.autosign
# Subtract DNSKEY TTL plus zone propagation delay from all the times (2h).
TpubN="now-4470h"
TactN="now-4445h"
TretN="now-6h"
TremN="now+621h"
TpubN1="now-9h"
TactN1="${TretN}"
TretN1="now+4458h"
TremN1="now+5085h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll1 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $U now-2h -d $H now-2h -z $U $TactN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O now-2h -z $R $TactN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 6:
# After the retire interval has passed the predecessor DNSKEY can be
# removed from the zone.
setup step6.csk-roll1.autosign
# According to RFC 7583:
# Trem(N) = Tret(N) + IretZ
# Tret(N) = Tact(N) + Lcsk
#
# Lcsk:   186d
# Iret:   4h
# IretZ:  26d3h
#
# Tpub(N)   = now - IretZ - Lcsk = now - 627h - 186d
#           = now - 627h - 4464h = now - 5091h
# Tact(N)   = now - 627h - 186d
# Tret(N)   = now - IretZ = now - 627h
# Trem(N)   = now
# Tpub(N+1) = now - IretZ - Ipub = now - 627h - 3h = now - 630h
# Tact(N+1) = Tret(N)
# Tret(N+1) = now - IretZ + Lcsk = now - 627h + 186d = now + 3837h
# Trem(N+1) = now + Lcsk = now + 186d
TpubN="now-5091h"
TactN="now-5066h"
TretN="now-627h"
TremN="now"
TpubN1="now-630h"
TactN1="${TretN}"
TretN1="now+3837h"
TremN1="now+186d"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll1 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $H $TremN -d $H $TremN -z $U $TactN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TremN -z $R $TactN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 7:
# Some time later the predecessor DNSKEY enters the HIDDEN state.
setup step7.csk-roll1.autosign
# Subtract DNSKEY TTL plus zone propagation delay from all the times (2h).
TpubN="now-5093h"
TactN="now-5068h"
TretN="now-629h"
TremN="now-2h"
TpubN1="now-632h"
TactN1="${TretN}"
TretN1="now+3835h"
TremN1="now+4462h"
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll1 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $U $TremN -r $H $TremN -d $H $TremN -z $H $TactN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TactN1 -z $O $TactN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 8:
# The predecessor DNSKEY can be purged.
setup step8.csk-roll1.autosign
TpubN="now-5094h"
TactN="now-5069h"
TretN="now-630h"
TremN="now-3h"
TpubN1="now-633h"
TactN1="${TretN}"
TretN1="now+3834h"
TremN1="now+4461h"
# Subtract purge-keys interval from all the times (1h).
keytimes="-P ${TpubN}  -P sync ${TactN}  -A ${TpubN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -P sync ${TactN1} -A ${TactN1} -I ${TretN1} -D ${TremN1}"
CSK1=$($KEYGEN -k csk-roll1 -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-roll1 -l kasp.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $H $TremN -r $H $TremN -d $H $TremN -z $H $TactN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TactN1 -z $O $TactN1 "$CSK2" >settime.out.$zone.2 2>&1
# Set key rollover relationship.
key_successor $CSK1 $CSK2
# Sign zone.
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -G "cdnskey,cds:sha-384" -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
