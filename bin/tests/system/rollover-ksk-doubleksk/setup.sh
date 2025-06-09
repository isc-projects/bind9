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
# The zones at ksk-doubleksk.autosign represent the various steps of a KSK
# Double-KSK rollover.
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.ksk-doubleksk.autosign
TactN="now-7d"
keytimes="-P ${TactN} -A ${TactN}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
cp $infile $zonefile
$SIGNER -S -x -G "cds:sha-256" -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 2:
# It is time to submit the introduce the new KSK.
setup step2.ksk-doubleksk.autosign
# Lksk:           60d
# Dreg:           n/a
# DprpC:          1h
# TTLds:          1d
# TTLkey:         2h
# publish-safety: 1d
# retire-safety:  2d
#
# According to RFC 7583:
# Tpub(N+1) <= Tact(N) + Lksk - Dreg - IpubC
# IpubC = DprpC + TTLkey (+publish-safety)
#
# IpubC   = 27h
# Tact(N) = now - Lksk + Dreg + IpubC = now - 60d + 27h
#         = now - 1440h + 27h = now - 1413h
TactN="now-1413h"
keytimes="-P ${TactN} -A ${TactN}"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -G "cds:sha-256" -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 3:
# It is time to submit the DS.
setup step3.ksk-doubleksk.autosign
# According to RFC 7583:
# Iret = DprpP + TTLds (+retire-safety)
#
# Iret       = 50h
# Tpub(N)    = now - Lksk = now - 60d = now - 60d
# Tact(N)    = now - 1413h
# Tret(N)    = now
# Trem(N)    = now + Iret = now + 50h
# Tpub(N+1)  = now - IpubC = now - 27h
# Tact(N+1)  = now
# Tret(N+1)  = now + Lksk = now + 60d
# Trem(N+1)  = now + Lksk + Iret = now + 60d + 50h
#            = now + 1440h + 50h = 1490h
TpubN="now-60d"
TactN="now-1413h"
TretN="now"
TremN="now+50h"
TpubN1="now-27h"
TactN1="now"
TretN1="now+60d"
TremN1="now+1490h"
ksktimes="-P ${TpubN}  -A ${TpubN}  -P sync ${TactN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -A ${TactN1} -P sync ${TactN1} -I ${TretN1} -D ${TremN1}"
zsktimes="-P ${TpubN}  -A ${TpubN}"
KSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $ksktimes $zone 2>keygen.out.$zone.1)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $newtimes $zone 2>keygen.out.$zone.2)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $zsktimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $H -k $O $TpubN -r $O $TpubN -d $O $TactN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -r $R $TpubN1 -d $H $TpubN1 "$KSK2" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TpubN -z $O $TpubN "$ZSK" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $KSK1 $KSK2
# Sign zone.
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -G "cds:sha-256" -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 4:
# The DS should be swapped now.
setup step4.ksk-doubleksk.autosign
# Tpub(N)    = now - Lksk - Iret = now - 60d - 50h
#            = now - 1440h - 50h = now - 1490h
# Tact(N)    = now - 1490h + 27h = now - 1463h
# Tret(N)    = now - Iret = now - 50h
# Trem(N)    = now
# Tpub(N+1)  = now - Iret - IpubC = now - 50h - 27h
#            = now - 77h
# Tact(N+1)  = Tret(N)
# Tret(N+1)  = now + Lksk - Iret = now + 60d - 50h = now + 1390h
# Trem(N+1)  = now + Lksk = now + 60d
TpubN="now-1490h"
TactN="now-1463h"
TretN="now-50h"
TremN="now"
TpubN1="now-77h"
TactN1="${TretN}"
TretN1="now+1390h"
TremN1="now+60d"
ksktimes="-P ${TpubN}  -A ${TpubN}  -P sync ${TactN}  -I ${TretN}   -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -A ${TactN1} -P sync ${TactN1} -I ${TretN1}  -D ${TremN1}"
zsktimes="-P ${TpubN}  -A ${TpubN}"
KSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $ksktimes $zone 2>keygen.out.$zone.1)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $newtimes $zone 2>keygen.out.$zone.2)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $zsktimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $U $TretN -D ds $TretN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $R $TactN1 -P ds $TactN1 "$KSK2" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $KSK1 $KSK2
# Sign zone.
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -G "cds:sha-256" -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 5:
# The predecessor DNSKEY is removed long enough that is has become HIDDEN.
setup step5.ksk-doubleksk.autosign
# Subtract DNSKEY TTL + zone-propagation-delay from all the times (3h).
# Tpub(N)    = now - 1490h - 3h = now - 1493h
# Tact(N)    = now - 1463h - 3h = now - 1466h
# Tret(N)    = now - 50h - 3h = now - 53h
# Trem(N)    = now - 3h
# Tpub(N+1)  = now - 77h - 3h = now - 80h
# Tact(N+1)  = Tret(N)
# Tret(N+1)  = now + 1390h - 3h = now + 1387h
# Trem(N+1)  = now + 60d - 3h = now + 1441h
TpubN="now-1493h"
TactN="now-1466h"
TretN="now-53h"
TremN="now-3h"
TpubN1="now-80h"
TactN1="${TretN}"
TretN1="now+1387h"
TremN1="now+1441h"
ksktimes="-P ${TpubN}  -A ${TpubN}  -P sync ${TactN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -A ${TactN1} -P sync ${TactN1} -I ${TretN1} -D ${TremN1}"
zsktimes="-P ${TpubN}  -A ${TpubN}"
KSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $ksktimes $zone 2>keygen.out.$zone.1)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $newtimes $zone 2>keygen.out.$zone.2)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $zsktimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $H -k $U $TretN -r $U $TretN -d $H $TretN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TactN1 "$KSK2" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $KSK1 $KSK2
# Sign zone.
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -G "cds:sha-256" -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 6:
# The predecessor DNSKEY can be purged.
setup step6.ksk-doubleksk.autosign
# Subtract purge-keys interval from all the times (1h).
TpubN="now-1494h"
TactN="now-1467h"
TretN="now-54h"
TremN="now-4h"
TpubN1="now-81h"
TactN1="${TretN}"
TretN1="now+1386h"
TremN1="now+1440h"
ksktimes="-P ${TpubN}  -A ${TpubN}  -P sync ${TactN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -A ${TactN1} -P sync ${TactN1} -I ${TretN1} -D ${TremN1}"
zsktimes="-P ${TpubN}  -A ${TpubN}"
KSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $ksktimes $zone 2>keygen.out.$zone.1)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $newtimes $zone 2>keygen.out.$zone.2)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $zsktimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $H -k $H $TretN -r $H $TretN -d $H $TretN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TactN1 "$KSK2" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $KSK1 $KSK2
# Sign zone.
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -G "cds:sha-256" -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
