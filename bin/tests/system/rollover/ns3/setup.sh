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
. ../../conf.sh

echo_i "ns3/setup.sh"

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

# Zone to test manual rollover.
setup manual-rollover.kasp
T="now-7d"
keytimes="-P $T -A $T"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -d $O $T -k $O $T -r $O $T "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $T -z $O $T "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -PS -x -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Multi-signer zones.
setup "multisigner-model2.kasp"
cp template.db.in "$zonefile"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -f KSK -L 3600 -M 32768:65535 $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -M 32768:65535 $zone 2>keygen.out.$zone.2)
cat "${KSK}.key" | grep -v ";.*" >>"${zone}.db"
cat "${ZSK}.key" | grep -v ";.*" >>"${zone}.db"
# Import a ZSK of another provider into the DNSKEY RRset.
ZSK1=$($KEYGEN -K ../ -a $DEFAULT_ALGORITHM -L 3600 -M 0:32767 $zone 2>keygen.out.$zone.3)
cat "../${ZSK1}.key" | grep -v ";.*" >>"${zone}.db"

# We are changing an existing single-signed zone to multi-signed
# zone where the key tags do not match the dnssec-policy key tag range
setup single-to-multisigner.kasp
T="now-7d"
S="now-8635mi" # T - 1d5m
keytimes="-P $T -A $T"
cdstimes="-P sync $S"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -M 0:32767 -L 3600 -f KSK $keytimes $cdstimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -M 0:32767 -L 3600 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -d $O $T -k $O $T -r $O $T "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $T -z $O $T "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
$SIGNER -PS -z -x -s now-2w -e now-1mi -o $zone -f "${zonefile}" $infile >signer.out.$zone.1 2>&1
echo "Lifetime: 0" >>"${KSK}".state
echo "Lifetime: 0" >>"${ZSK}".state

#
# The zones at enable-dnssec.autosign represent the various steps of the
# initial signing of a zone.
#

# Step 1:
# This is an unsigned zone and named should perform the initial steps of
# introducing the DNSSEC records in the right order.
setup step1.enable-dnssec.autosign
cp template.db.in $zonefile

# Step 2:
# The DNSKEY has been published long enough to become OMNIPRESENT.
setup step2.enable-dnssec.autosign
# DNSKEY TTL:             300 seconds
# zone-propagation-delay: 5 minutes (300 seconds)
# publish-safety:         5 minutes (300 seconds)
# Total:                  900 seconds
TpubN="now-900s"
keytimes="-P ${TpubN} -A ${TpubN}"
CSK=$($KEYGEN -k enable-dnssec -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $R $TpubN -r $R $TpubN -d $H $TpubN -z $R $TpubN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 3:
# The zone signatures have been published long enough to become OMNIPRESENT.
setup step3.enable-dnssec.autosign
# Passed time since publication:
# max-zone-ttl:           12 hours (43200 seconds)
# zone-propagation-delay: 5 minutes (300 seconds)
TpubN="now-43500s"
# We can submit the DS now.
keytimes="-P ${TpubN} -A ${TpubN}"
CSK=$($KEYGEN -k enable-dnssec -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TpubN -r $O $TpubN -d $H $TpubN -z $R $TpubN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 4:
# The DS has been submitted long enough ago to become OMNIPRESENT.
setup step4.enable-dnssec.autosign
# DS TTL:                    2 hour (7200 seconds)
# parent-propagation-delay:  1 hour (3600 seconds)
# Total aditional time:      10800 seconds
# 43500 + 10800 = 54300
TpubN="now-54300s"
TsbmN="now-10800s"
keytimes="-P ${TpubN} -A ${TpubN} -P sync ${TsbmN}"
CSK=$($KEYGEN -k enable-dnssec -l kasp.conf $keytimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -P ds $TsbmN -k $O $TpubN -r $O $TpubN -d $R $TpubN -z $O $TsbmN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -s now-1h -e now+30d -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

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

# Test #2375, the "three is a crowd" bug, where a new key is introduced but the
# previous rollover has not finished yet. In other words, we have a key KEY2
# that is the successor of key KEY1, and we introduce a new key KEY3 that is
# the successor of key KEY2:
#
#     KEY1 < KEY2 < KEY3.
#
# The expected behavior is that all three keys remain in the zone, and not
# the bug behavior where KEY2 is removed and immediately replaced with KEY3.
#
# Set up a zone that has a KSK (KEY1) and have the successor key (KEY2)
# published as well.
setup three-is-a-crowd.kasp
# These times are the same as step3.ksk-doubleksk.autosign.
TpubN="now-60d"
TactN="now-1413h"
TretN="now"
TremN="now+50h"
TpubN1="now-27h"
TsbmN1="now"
TactN1="${TretN}"
TretN1="now+60d"
TremN1="now+1490h"
ksktimes="-P ${TpubN}  -A ${TpubN}  -P sync ${TactN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -A ${TactN1} -P sync ${TsbmN1} -I ${TretN1} -D ${TremN1}"
zsktimes="-P ${TpubN}  -A ${TpubN}"
KSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $ksktimes $zone 2>keygen.out.$zone.1)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $newtimes $zone 2>keygen.out.$zone.2)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $zsktimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $O $TactN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -r $R $TpubN1 -d $H $TpubN1 "$KSK2" >settime.out.$zone.2 2>&1
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
