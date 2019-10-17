#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. "$SYSTEMTESTTOP/conf.sh"

echo_i "ns3/setup.sh"

setup() {
	zone="$1"
	echo_i "setting up zone: $zone"
	zonefile="${zone}.db"
	infile="${zone}.db.infile"
	echo $zone >> zones
}

private_type_record() {
	_zone=$1
	_algorithm=$2
	_keyfile=$3

	_id=$(keyfile_to_key_id "$_keyfile")

	printf "%s. 0 IN TYPE65534 \# 5 %02x%04x0000\n" $_zone $_algorithm $_id
}


# Make lines shorter by storing key states in environment variables.
H="HIDDEN"
R="RUMOURED"
O="OMNIPRESENT"
U="UNRETENTIVE"

#
# Set up zones that will be initially signed.
#
for zn in default rsasha1 dnssec-keygen some-keys legacy-keys pregenerated \
	  rsasha1-nsec3 rsasha256 rsasha512 ecdsa256 ecdsa384
do
	setup "${zn}.kasp"
	cp template.db.in $zonefile
done

# Some of these zones already have keys.
zone="dnssec-keygen.kasp"
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.1 2>&1

zone="some-keys.kasp"
$KEYGEN -P none -A none -a RSASHA1 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -P none -A none -a RSASHA1 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="legacy.kasp"
$KEYGEN -a RSASHA1 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -a RSASHA1 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="pregenerated.kasp"
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.1 2>&1
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.2 2>&1

#
# Set up zones that are already signed.
#

# These signatures are set to expire long in the past, update immediately.
setup expired-sigs.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 300 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 300 $zone 2> keygen.out.$zone.2`
T="now-6mo"
$SETTIME -s -P $T -A $T  -g $O  -d $O $T -k $O $T -r $O $T $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $T -A $T  -g $O  -k $O $T -z $O $T $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -PS -x -s now-2mo -e now-1mo -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# These signatures are still good, and can be reused.
setup fresh-sigs.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 300 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 300 $zone 2> keygen.out.$zone.2`
T="now-6mo"
$SETTIME -s -P $T -A $T  -g $O  -d $O $T -k $O $T -r $O $T $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $T -A $T  -g $O  -k $O $T -z $O $T $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# These signatures are still good, but not fresh enough, update immediately.
setup unfresh-sigs.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 300 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 300 $zone 2> keygen.out.$zone.2`
T="now-6mo"
$SETTIME -s -P $T -A $T  -g $O  -d $O $T -k $O $T -r $O $T $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $T -A $T  -g $O  -k $O $T -z $O $T $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1w -e now+1w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# These signatures are already expired, and the private ZSK is missing.
setup zsk-missing.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 300 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 300 $zone 2> keygen.out.$zone.2`
T="now-6mo"
$SETTIME -s -P $T -A $T  -g $O  -d $O $T -k $O $T -r $O $T $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $T -A $T  -g $O  -k $O $T -z $O $T $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -PS -x -s now-2w -e now-1mi -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1
rm -f ${ZSK}.private

# These signatures are already expired, and the private ZSK is retired.
setup zsk-retired.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 300 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 300 $zone 2> keygen.out.$zone.2`
T="now-6mo"
$SETTIME -s -P $T -A $T  -g $O  -d $O $T -k $O $T -r $O $T $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $T -A $T  -g $O  -k $O $T -z $O $T $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -PS -x -s now-2w -e now-1mi -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1
$SETTIME -s -I now -g HIDDEN $ZSK > settime.out.$zone.3 2>&1

#
# The zones at zsk-prepub.autosign represent the various steps of a ZSK
# Pre-Publication rollover.
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.zsk-prepub.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 3600 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.2`
TactN="now"
$SETTIME -s -P $TactN -A $TactN  -g $O -k $O $TactN -r $O $TactN -d $O $TactN $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN -A $TactN  -g $O -k $O $TactN -z $O $TactN              $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 2:
# It is time to pre-publish the successor ZSK.
setup step2.zsk-prepub.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 3600 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.2`
# According to RFC 7583: Tpub(N+1) <= Tact(N) + Lzsk - Ipub
# Also: Ipub = Dprp + TTLkey (+publish-safety)
# so:   Tact(N) = Tpub(N+1) + Ipub - Lzsk = now + (1d2h) - 30d =
#       now + 26h - 30d = now − 694h
TactN="now-694h"
$SETTIME -s -P $TactN -A $TactN  -g $O -k $O $TactN -r $O $TactN -d $O $TactN $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN -A $TactN  -g $O -k $O $TactN -z $O $TactN              $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 3:
# After the publication interval has passed the DNSKEY of the successor ZSK
# is OMNIPRESENT and the zone can thus be signed with the successor ZSK.
setup step3.zsk-prepub.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 3600 $zone 2> keygen.out.$zone.1`
ZSK1=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.2`
ZSK2=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.3`
# According to RFC 7583: Tpub(N+1) <= Tact(N) + Lzsk - Ipub
# Also: Tret(N) = Tact(N+1) = Tact(N) + Lzsk
# so:   Tact(N) = Tact(N+1) - Lzsk = now - 30d
# and:  Tpub(N+1) = Tact(N+1) - Ipub = now - 26h
# and:  Tret(N+1) = Tact(N+1) + Lzsk
TactN="now-30d"
TpubN1="now-26h"
TretN1="now+30d"
$SETTIME -s -P $TactN  -A $TactN            -g $O -k $O $TactN  -r $O $TactN -d $O $TactN $KSK  > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN  -A $TactN -I now     -g $H -k $O $TactN  -z $O $TactN              $ZSK1 > settime.out.$zone.2 2>&1
$SETTIME -s -S $ZSK1             -i 0                                                     $ZSK2 > settime.out.$zone.3 2>&1
$SETTIME -s -P $TpubN1 -A now    -I $TretN1 -g $O -k $R $TpubN1 -z $H $TpubN1             $ZSK2 > settime.out.$zone.4 2>&1
cat template.db.in "${KSK}.key" "${ZSK1}.key" "${ZSK2}.key" > "$infile"
private_type_record $zone 13 $KSK  >> "$infile"
private_type_record $zone 13 $ZSK1 >> "$infile"
private_type_record $zone 13 $ZSK2 >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 4:
# After the retire interval has passed the predecessor DNSKEY can be
# removed from the zone.
setup step4.zsk-prepub.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 3600 $zone 2> keygen.out.$zone.1`
ZSK1=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.2`
ZSK2=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.3`
# According to RFC 7583: Tret(N) = Tact(N) + Lzsk
# Also: Tdea(N) = Tret(N) + Iret
# Also: Iret = Dsgn + Dprp + TTLsig (+retire-safety)
# so:   Tact(N) = Tdea(N) - Iret - Lzsk = now - (1w1h1d2d) - 30d =
#       now - (10d1h) - 30d = now - 961h
# and:  Tret(N) = Tdea(N) - Iret = now - (10d1h) = now - 241h
# and:  Tpub(N+1) = Tdea(N) - Iret - Ipub = now - (10d1h) - 26h =
#       now - 267h
# and:  Tact(N+1) = Tdea(N) - Iret = Tret(N)
# and:  Tret(N+1) = Tdea(N) - Iret + Lzsk = now - (10d1h) + 30d =
#       now + 479h
TactN="now-961h"
TretN="now-241h"
TpubN1="now-267h"
TactN1="${TretN}"
TretN1="now+479h"
$SETTIME -s -P $TactN  -A $TactN             -g $O -k $O $TactN  -r $O $TactN -d $O $TactN $KSK  > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN  -A $TactN  -I $TretN  -g $H -k $O $TactN  -z $U $TretN              $ZSK1 > settime.out.$zone.2 2>&1
$SETTIME -s -S $ZSK1              -i 0                                                     $ZSK2 > settime.out.$zone.3 2>&1
$SETTIME -s -P $TpubN1 -A $TactN1 -I $TretN1 -g $O -k $O $TactN1 -z $R $TactN1             $ZSK2 > settime.out.$zone.4 2>&1
cat template.db.in "${KSK}.key" "${ZSK1}.key" "${ZSK2}.key" > "$infile"
$SIGNER -PS -x -s now-2w -e now-1mi -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 5:
# The predecessor DNSKEY is removed long enough that is has become HIDDEN.
setup step5.zsk-prepub.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 3600 $zone 2> keygen.out.$zone.1`
ZSK1=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.2`
ZSK2=`$KEYGEN -a ECDSAP256SHA256 -L 3600 $zone 2> keygen.out.$zone.3`
# Substract DNSKEY TTL from all the times (1h).
TactN="now-962h"
TretN="now-242h"
TpubN1="now-268h"
TactN1="${TretN}"
TretN1="now+478h"
$SETTIME -s -P $TactN  -A $TactN                   -g $O -k $O $TactN  -r $O $TactN -d $O $TactN $KSK  > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN  -A $TactN  -I $TretN -D now -g $H -k $U $TretN  -z $U $TretN              $ZSK1 > settime.out.$zone.2 2>&1
$SETTIME -s -S $ZSK1              -i 0                                                           $ZSK2 > settime.out.$zone.3 2>&1
$SETTIME -s -P $TpubN1 -A $TactN1 -I $TretN1       -g $O -k $O $TactN1 -z $R $TactN1             $ZSK2 > settime.out.$zone.4 2>&1
cat template.db.in "${KSK}.key" "${ZSK1}.key" "${ZSK2}.key" > "$infile"
private_type_record $zone 13 $KSK  >> "$infile"
private_type_record $zone 13 $ZSK1 >> "$infile"
private_type_record $zone 13 $ZSK2 >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

#
# The zones at ksk-doubleksk.autosign represent the various steps of a KSK
# Double-KSK rollover.
#

# Step 1:
# Introduce the first key. This will immediately be active.
setup step1.ksk-doubleksk.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 7200 $zone 2> keygen.out.$zone.2`
TactN="now"
$SETTIME -s -P $TactN -A $TactN -g $O -k $O $TactN -r $O $TactN -d $O $TactN $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN -A $TactN -g $O              -k $O $TactN -z $O $TactN $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 2:
# It is time to submit the introduce the new KSK.
setup step2.ksk-doubleksk.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 7200 $zone 2> keygen.out.$zone.2`
# According to RFC 7583: Tpub(N+1) <= Tact(N) + Lksk - Dreg - IpubC
# Also: IpubC = DprpC + TTLkey (+publish-safety)
# so:   Tact(N) = Tpub(N+1) - Lksk + Dreg + IpubC = now - 60d + (1d3h)
#       now - 1440h + 27h = now - 1413h
TactN="now-1413h"
$SETTIME -s -P $TactN -A $TactN -g $O -k $O $TactN -r $O $TactN -d $O $TactN $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN -A $TactN -g $O -k $O $TactN -z $O $TactN              $ZSK > settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 3:
# It is time to submit the DS.
setup step3.ksk-doubleksk.autosign
KSK1=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.1`
KSK2=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.2`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 7200 $zone 2> keygen.out.$zone.3`
# According to RFC 7583: Tsbm(N+1) >= Trdy(N+1)
# Also: Tact(N+1) = Tsbm(N+1) + Dreg
# so:   Tact(N) = Tsbm(N+1) + Dreg - Lksk = now + 1d - 60d = now - 59d
# and:  Tret(N) = Tsbm(N+1) + Dreg = now + 1d
# and:  Tpub(N+1) <= Tsbm(N+1) - IpubC = now + 27h
# and:  Tret(N+1) = Tsbm(N+1) + Dreg + Lksk = 1d + 60d
TactN="now-59d"
TretN="now+1d"
TpubN1="now-27h"
TretN1="now+61d"
$SETTIME -s -P $TactN  -A $TactN  -I $TretN  -g $H -k $O $TactN   -r $O $TactN  -d $O $TactN  $KSK1 > settime.out.$zone.1 2>&1
$SETTIME -s -S $KSK1              -i 0                                                        $KSK2 > settime.out.$zone.3 2>&1
$SETTIME -s -P $TpubN1 -A $TretN  -I $TretN1 -g $O -k $R $TpubN1  -r $R $TpubN1 -d $H $TpubN1 $KSK2 > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN  -A $TactN             -g $O -k $O $TactN   -z $O $TactN                $ZSK  > settime.out.$zone.2 2>&1
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK1 >> "$infile"
private_type_record $zone 13 $KSK2 >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 4:
# The DS should be swapped now.
setup step4.ksk-doubleksk.autosign
KSK1=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.1`
KSK2=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.2`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 7200 $zone 2> keygen.out.$zone.3`
# According to RFC 7583: Tdea(N) = Tret(N) + Iret
# Also: Tret(N) = Tsbm(N+1) + Dreg
# Also: Tact(N+1) = Tret(N)
# Also: Iret = DprpP + TTLds (+retire-safety)
# so:   Tact(N) = Tdea(N) - Lksk - Iret = now - 60d - 2d2h = now - 1490h
# and:  Tret(N) = Tdea(N) - Iret = now - 2d2h = 50h
# and:  Tpub(N+1) = Tdea(N) - Iret - Dreg - IpubC = now - 50h - 1d - 1d3h = now - 101h
# and:  Tsbm(N+1) = Tdea(N) - Iret - Dreg = now - 50h - 1d = now - 74h
# and:  Tact(N+1) = Tret(N)
# and:  Tret(N+1) = Tdea(N) + Lksk - Iret = now + 60d - 2d2h = now + 1390h
TactN="now-1490h"
TretN="now-50h"
TpubN1="now-101h"
TsbmN1="now-74h"
TactN1="${TretN}"
TretN1="now+1390h"
$SETTIME -s -P $TactN  -A $TactN  -I $TretN  -g $H -k $O $TactN  -r $O $TactN  -d $U $TsbmN1 $KSK1 > settime.out.$zone.1 2>&1
$SETTIME -s -S $KSK1              -i 0                                                       $KSK2 > settime.out.$zone.3 2>&1
$SETTIME -s -P $TpubN1 -A $TactN1 -I $TretN1 -g $O -k $O $TsbmN1 -r $O $TsbmN1 -d $R $TsbmN1 $KSK2 > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN  -A $TactN             -g $O -k $O $TactN  -z $O $TactN                $ZSK  > settime.out.$zone.2 2>&1
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK1 >> "$infile"
private_type_record $zone 13 $KSK2 >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1

# Step 5:
# The predecessor DNSKEY is removed long enough that is has become HIDDEN.
setup step5.ksk-doubleksk.autosign
KSK1=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.1`
KSK2=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 7200 $zone 2> keygen.out.$zone.2`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 7200 $zone 2> keygen.out.$zone.3`
# Substract DNSKEY TTL from all the times (2h).
TactN="now-1492h"
TretN="now-52h"
TpubN1="now-102h"
TsbmN1="now-75h"
TactN1="${TretN}"
TretN1="now+1388h"
$SETTIME -s -P $TactN  -A $TactN  -I $TretN  -g $H -k $U $TretN  -r $U $TretN  -d $H $TretN  $KSK1 > settime.out.$zone.1 2>&1
$SETTIME -s -S $KSK1              -i 0                                                       $KSK2 > settime.out.$zone.3 2>&1
$SETTIME -s -P $TpubN1 -A $TactN1 -I $TretN1 -g $O -k $O $TactN1 -r $O $TactN1 -d $O $TactN1 $KSK2 > settime.out.$zone.1 2>&1
$SETTIME -s -P $TactN  -A $TactN             -g $O -k $O $TactN  -z $O $TactN                $ZSK  > settime.out.$zone.2 2>&1
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" > "$infile"
private_type_record $zone 13 $KSK1 >> "$infile"
private_type_record $zone 13 $KSK2 >> "$infile"
private_type_record $zone 13 $ZSK >> "$infile"
$SIGNER -S -x -s now-1h -e now+2w -o $zone -O full -f $zonefile $infile > signer.out.$zone.1 2>&1
