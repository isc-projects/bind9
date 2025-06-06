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
# The zones at algorithm-roll.kasp represent the various steps of a ZSK/KSK
# algorithm rollover.
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.algorithm-roll.kasp
echo "$zone" >>zones
TactN="now-7d"
TsbmN="now-161h"
ksktimes="-P ${TactN} -A ${TactN}"
zsktimes="-P ${TactN} -A ${TactN}"
KSK=$($KEYGEN -a RSASHA256 -L 3600 -f KSK $ksktimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a RSASHA256 -L 3600 $zsktimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -k $O $TactN -r $O $TactN -d $O $TactN "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
private_type_record $zone 8 "$KSK" >>"$infile"
private_type_record $zone 8 "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 2:
# After the publication interval has passed the DNSKEY is OMNIPRESENT.
setup step2.algorithm-roll.kasp
# The time passed since the new algorithm keys have been introduced is 3 hours.
TpubN1="now-3h"
# Tsbm(N+1) = TpubN1 + Ipub = now + TTLsig + Dprp = now - 3h + 6h + 1h = now + 4h
TsbmN1="now+4h"
ksk1times="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN} -I ${TsbmN1}"
zsk1times="-P ${TactN}  -A ${TactN}  -I ${TsbmN1}"
ksk2times="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
zsk2times="-P ${TpubN1} -A ${TpubN1}"
KSK1=$($KEYGEN -a RSASHA256 -L 3600 -f KSK $ksk1times $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a RSASHA256 -L 3600 $zsk1times $zone 2>keygen.out.$zone.2)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $ksk2times $zone 2>keygen.out.$zone.3)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $zsk2times $zone 2>keygen.out.$zone.4)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $O $TactN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $O $TactN -z $O $TactN "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -r $R $TpubN1 -d $H $TpubN1 "$KSK2" >settime.out.$zone.3 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -z $R $TpubN1 "$ZSK2" >settime.out.$zone.4 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${KSK1}.state"
echo "Lifetime: 0" >>"${ZSK1}.state"
cat template.db.in "${KSK1}.key" "${ZSK1}.key" "${KSK2}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone 8 "$KSK1" >>"$infile"
private_type_record $zone 8 "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 3:
# The zone signatures are also OMNIPRESENT.
setup step3.algorithm-roll.kasp
# The time passed since the new algorithm keys have been introduced is 7 hours.
TpubN1="now-7h"
TsbmN1="now"
ksk1times="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN}  -I ${TsbmN1}"
zsk1times="-P ${TactN}  -A ${TactN}  -I ${TsbmN1}"
ksk2times="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
zsk2times="-P ${TpubN1} -A ${TpubN1}"
KSK1=$($KEYGEN -a RSASHA256 -L 3600 -f KSK $ksk1times $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a RSASHA256 -L 3600 $zsk1times $zone 2>keygen.out.$zone.2)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $ksk2times $zone 2>keygen.out.$zone.3)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $zsk2times $zone 2>keygen.out.$zone.4)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $O $TactN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $O $TactN -z $O $TactN "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -r $O $TpubN1 -d $H $TpubN1 "$KSK2" >settime.out.$zone.3 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -z $R $TpubN1 "$ZSK2" >settime.out.$zone.4 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${KSK1}.state"
echo "Lifetime: 0" >>"${ZSK1}.state"
cat template.db.in "${KSK1}.key" "${ZSK1}.key" "${KSK2}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone 8 "$KSK1" >>"$infile"
private_type_record $zone 8 "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 4:
# The DS is swapped and can become OMNIPRESENT.
setup step4.algorithm-roll.kasp
# The time passed since the DS has been swapped is 3 hours.
TpubN1="now-10h"
TsbmN1="now-3h"
ksk1times="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN}  -I ${TsbmN1}"
zsk1times="-P ${TactN}  -A ${TactN}  -I ${TsbmN1}"
ksk2times="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
zsk2times="-P ${TpubN1} -A ${TpubN1}"
KSK1=$($KEYGEN -a RSASHA256 -L 3600 -f KSK $ksk1times $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a RSASHA256 -L 3600 $zsk1times $zone 2>keygen.out.$zone.2)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $ksk2times $zone 2>keygen.out.$zone.3)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $zsk2times $zone 2>keygen.out.$zone.4)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $U $TsbmN1 -D ds $TsbmN1 "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $O $TactN -z $O $TactN "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -r $O $TpubN1 -d $R $TsbmN1 -P ds $TsbmN1 "$KSK2" >settime.out.$zone.3 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -z $R $TpubN1 "$ZSK2" >settime.out.$zone.4 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${KSK1}.state"
echo "Lifetime: 0" >>"${ZSK1}.state"
cat template.db.in "${KSK1}.key" "${ZSK1}.key" "${KSK2}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone 8 "$KSK1" >>"$infile"
private_type_record $zone 8 "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 5:
# The DNSKEY is removed long enough to be HIDDEN.
setup step5.algorithm-roll.kasp
# The time passed since the DNSKEY has been removed is 2 hours.
TpubN1="now-12h"
TsbmN1="now-5h"
ksk1times="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN}  -I ${TsbmN1}"
zsk1times="-P ${TactN}  -A ${TactN}  -I ${TsbmN1}"
ksk2times="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
zsk2times="-P ${TpubN1} -A ${TpubN1}"
KSK1=$($KEYGEN -a RSASHA256 -L 3600 -f KSK $ksk1times $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a RSASHA256 -L 3600 $zsk1times $zone 2>keygen.out.$zone.2)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $ksk2times $zone 2>keygen.out.$zone.3)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $zsk2times $zone 2>keygen.out.$zone.4)
$SETTIME -s -g $H -k $U $TsbmN1 -r $U $TsbmN1 -d $H $TsbmN1 "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $U $TsbmN1 -z $U $TsbmN1 "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -r $O $TpubN1 -d $O $TsbmN1 "$KSK2" >settime.out.$zone.3 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -z $R $TpubN1 "$ZSK2" >settime.out.$zone.4 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${KSK1}.state"
echo "Lifetime: 0" >>"${ZSK1}.state"
cat template.db.in "${KSK1}.key" "${ZSK1}.key" "${KSK2}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone 8 "$KSK1" >>"$infile"
private_type_record $zone 8 "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

# Step 6:
# The RRSIGs have been removed long enough to be HIDDEN.
setup step6.algorithm-roll.kasp
# Additional time passed: 7h.
TpubN1="now-19h"
TsbmN1="now-12h"
ksk1times="-P ${TactN}  -A ${TactN}  -P sync ${TsbmN}  -I ${TsbmN1}"
zsk1times="-P ${TactN}  -A ${TactN}  -I ${TsbmN1}"
ksk2times="-P ${TpubN1} -A ${TpubN1} -P sync ${TsbmN1}"
zsk2times="-P ${TpubN1} -A ${TpubN1}"
KSK1=$($KEYGEN -a RSASHA256 -L 3600 -f KSK $ksk1times $zone 2>keygen.out.$zone.1)
ZSK1=$($KEYGEN -a RSASHA256 -L 3600 $zsk1times $zone 2>keygen.out.$zone.2)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $ksk2times $zone 2>keygen.out.$zone.3)
ZSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $zsk2times $zone 2>keygen.out.$zone.4)
$SETTIME -s -g $H -k $H $TsbmN1 -r $U $TsbmN1 -d $H $TsbmN1 "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $H -k $H $TsbmN1 -z $U $TsbmN1 "$ZSK1" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -r $O $TpubN1 -d $O $TsbmN1 "$KSK2" >settime.out.$zone.3 2>&1
$SETTIME -s -g $O -k $O $TpubN1 -z $R $TpubN1 "$ZSK2" >settime.out.$zone.4 2>&1
# Fake lifetime of old algorithm keys.
echo "Lifetime: 0" >>"${KSK1}.state"
echo "Lifetime: 0" >>"${ZSK1}.state"
cat template.db.in "${KSK1}.key" "${ZSK1}.key" "${KSK2}.key" "${ZSK2}.key" >"$infile"
private_type_record $zone 8 "$KSK1" >>"$infile"
private_type_record $zone 8 "$ZSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK2" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
