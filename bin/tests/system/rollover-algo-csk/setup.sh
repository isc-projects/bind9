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

cd "ns6"

setup() {
  zone="$1"
  echo_i "setting up zone: $zone"
  zonefile="${zone}.db"
  infile="${zone}.db.infile"
}

# Make lines shorter by storing key states in environment variables.
H="HIDDEN"
R="RUMOURED"
O="OMNIPRESENT"
U="UNRETENTIVE"

#
# The zones at csk-algorithm-roll.kasp represent the various steps of a CSK
# algorithm rollover.
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.csk-algorithm-roll.kasp
echo "$zone" >>zones
TactN="now-7d"
TsbmN="now-161h"
csktimes="-P ${TactN} -A ${TactN}"
CSK=$($KEYGEN -k csk-algoroll -l csk1.conf $csktimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -z $O $TactN -d $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone 5 "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -z -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 2:
# After the publication interval has passed the DNSKEY is OMNIPRESENT.
setup step2.csk-algorithm-roll.kasp
# The time passed since the new algorithm keys have been introduced is 3 hours.
TpubN1="now-3h"
# Tsbm(N+1) = TpubN1 + Ipub = now + TTLsig + Dprp = now - 3h + 6h + 1h = now + 4h
TsbmN1="now+4h"
csktimes="-P ${TactN}  -A ${TactN} -P sync ${TsbmN} -I now"
newtimes="-P ${TpubN1} -A ${TpubN1}"
CSK1=$($KEYGEN -k csk-algoroll -l csk1.conf $csktimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-algoroll -l csk2.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -z $O $TactN -d $O $TactN "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -r $R $TpubN1 -z $R $TpubN1 -d $H $TpubN1 "$CSK2" >settime.out.$zone.2 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${CSK1}.state"
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone 5 "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -z -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 3:
# The zone signatures are also OMNIPRESENT.
setup step3.csk-algorithm-roll.kasp
# The time passed since the new algorithm keys have been introduced is 7 hours.
TpubN1="now-7h"
TsbmN1="now"
ckstimes="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN} -I ${TsbmN1}"
newtimes="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
CSK1=$($KEYGEN -k csk-algoroll -l csk1.conf $csktimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-algoroll -l csk2.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -z $O $TactN -d $O $TactN "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -r $O $TpubN1 -z $R $TpubN1 -d $H $TpubN1 "$CSK2" >settime.out.$zone.2 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${CSK1}.state"
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone 5 "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -z -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 4:
# The DS is swapped and can become OMNIPRESENT.
setup step4.csk-algorithm-roll.kasp
# The time passed since the DS has been swapped is 3 hours.
TpubN1="now-10h"
TsbmN1="now-3h"
csktimes="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN} -I ${TsbmN1}"
newtimes="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
CSK1=$($KEYGEN -k csk-algoroll -l csk1.conf $csktimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-algoroll -l csk2.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -z $O $TsbmN1 -d $U $TsbmN1 -D ds $TsbmN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -r $O $TpubN1 -z $O $TsbmN1 -d $R $TsbmN1 -P ds $TsbmN1 "$CSK2" >settime.out.$zone.2 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${CSK1}.state"
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone 5 "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -z -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 5:
# The DNSKEY is removed long enough to be HIDDEN.
setup step5.csk-algorithm-roll.kasp
# The time passed since the DNSKEY has been removed is 2 hours.
TpubN1="now-12h"
TsbmN1="now-5h"
csktimes="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN} -I ${TsbmN1}"
newtimes="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
CSK1=$($KEYGEN -k csk-algoroll -l csk1.conf $csktimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-algoroll -l csk2.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $U $TactN -r $U $TactN -z $U $TsbmN1 -d $H $TsbmN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -r $O $TpubN1 -z $O $TsbmN1 -d $O $TsbmN1 "$CSK2" >settime.out.$zone.2 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${CSK1}.state"
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone 5 "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -z -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 6:
# The RRSIGs have been removed long enough to be HIDDEN.
setup step6.csk-algorithm-roll.kasp
# Additional time passed: 7h.
TpubN1="now-19h"
TsbmN1="now-12h"
csktimes="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN} -I ${TsbmN1}"
newtimes="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
CSK1=$($KEYGEN -k csk-algoroll -l csk1.conf $csktimes $zone 2>keygen.out.$zone.1)
CSK2=$($KEYGEN -k csk-algoroll -l csk2.conf $newtimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $H -k $H $TactN -r $U $TactN -z $U $TactN -d $H $TsbmN1 "$CSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN1 -r $O $TactN1 -z $O $TsubN1 -d $O $TsbmN1 "$CSK2" >settime.out.$zone.2 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${CSK1}.state"
cat template.db.in "${CSK1}.key" "${CSK2}.key" >"$infile"
private_type_record $zone 5 "$CSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -z -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
