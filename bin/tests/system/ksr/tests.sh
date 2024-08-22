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

# shellcheck source=conf.sh
. ../conf.sh
# shellcheck source=kasp.sh
. ../kasp.sh

set -e

RNDCCMD="$RNDC -c ../_common/rndc.conf -p ${CONTROLPORT} -s"

CDS_SHA1="no"
CDS_SHA256="yes"
CDS_SHA384="no"
CDNSKEY="yes"

status=0
n=0

# Get timing metadata from a value plus additional time.
# $1: Value
# $2: Additional time
addtime() {
  if [ -x "$PYTHON" ]; then
    # Convert "%Y%m%d%H%M%S" format to epoch seconds.
    # Then, add the additional time (can be negative).
    _value=$1
    _plus=$2
    $PYTHON >python.out <<EOF
from datetime import datetime
from datetime import timedelta
_now = datetime.strptime("$_value", "%Y%m%d%H%M%S")
_delta = timedelta(seconds=$_plus)
_then = _now + _delta
print(_then.strftime("%Y%m%d%H%M%S"));
EOF
    cat python.out
  fi
}

# Check keys that were created. The keys created are listed in the latest ksr
# output file, ksr.keygen.out.$n.
# $1: zone name
# $2: key directory
# $3: offset
ksr_check_keys() (
  zone=$1
  dir=$2
  offset=$3
  lifetime=$LIFETIME
  alg=$ALG
  size=$SIZE
  inception=0
  pad=$(printf "%03d" "$alg")

  num=0
  for key in $(grep "K${zone}.+$pad+" ksr.keygen.out.$n); do
    grep "; Created:" "${dir}/${key}.key" >created.out || return 1
    created=$(awk '{print $3}' <created.out)
    test "$num" -eq 0 && retired=$(addtime $created $offset)
    # active: retired previous key
    active=$retired
    # published: 2h5m (dnskey-ttl + publish-safety + propagation)
    published=$(addtime $active -7500)
    # retired: zsk-lifetime
    retired=$(addtime $active $lifetime)
    # removed: 10d1h5m (ttlsig + retire-safety + sign-delay + propagation)
    removed=$(addtime $retired 867900)

    echo_i "check metadata on $key: $alg $size $lifetime $published $active $retired $removed"
    statefile="${dir}/${key}.state"
    grep "Algorithm: $alg" $statefile >/dev/null || return 1
    grep "Length: $size" $statefile >/dev/null || return 1
    grep "Lifetime: $lifetime" $statefile >/dev/null || return 1
    grep "KSK: no" $statefile >/dev/null || return 1
    grep "ZSK: yes" $statefile >/dev/null || return 1
    grep "Published: $published" $statefile >/dev/null || return 1
    grep "Active: $active" $statefile >/dev/null || return 1
    grep "Retired: $retired" $statefile >/dev/null || return 1
    grep "Removed: $removed" $statefile >/dev/null || return 1

    inception=$((inception + lifetime))
    num=$((num + 1))

    # Save some information for testing
    cp ${dir}/${key}.key ${key}.key.expect
    cp ${dir}/${key}.private ${key}.private.expect
    cp ${dir}/${key}.state ${key}.state.expect
    cat ${dir}/${key}.key | grep -v ";.*" >"${zone}.${alg}.zsk${num}"
    echo $key >"${zone}.${alg}.zsk${num}.id"
  done

  return 0
)

# Print the DNSKEY records for zone $1, which have keys listed in file $5
# that match the keys with numbers $2 and $3, and match algorithm number $4,
# sorted by keytag.
print_dnskeys() {
  for key in $(cat $5 | sort); do
    for num in $2 $3; do
      zsk=$(cat $1.$4.zsk$num.id)
      if [ "$key" = "$zsk" ]; then
        cat $1.$4.zsk$num >>ksr.request.expect.$n
      fi
    done
  done
}
# Call the dnssec-ksr command:
# ksr <policy> [options] <command> <zone>
ksr() {
  $KSR -l ns1/named.conf -k "$@"
}

# Unknown action.
n=$((n + 1))
echo_i "check that 'dnssec-ksr' errors on unknown action ($n)"
ret=0
ksr common foobar common.test >ksr.foobar.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: unknown command 'foobar'" ksr.foobar.out.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Key generation: common
set_zsk() {
  ALG=$1
  SIZE=$2
  LIFETIME=$3
}

n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' errors on missing end date ($n)"
ret=0
ksr common keygen common.test >ksr.keygen.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: keygen requires an end date" ksr.keygen.out.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' pregenerates right amount of keys in the common case ($n)"
ret=0
ksr common -K ns1 -i now -e +1y keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
ksr_check_keys common.test ns1 0 || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# save now time
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
grep "; Created:" "ns1/${key}.key" >now.out || ret=1
now=$(awk '{print $3}' <now.out)

n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' selects pregenerated keys for the same time bundle ($n)"
ret=0
ksr common -K ns1 -e +1y keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
diff -w ksr.keygen.out.expect ksr.keygen.out.$n >/dev/null || ret=1
for key in $(cat ksr.keygen.out.$n); do
  # Ensure the files are not modified.
  diff ns1/${key}.key ${key}.key.expect >/dev/null || ret=1
  diff ns1/${key}.private ${key}.private.expect >/dev/null || ret=1
  diff ns1/${key}.state ${key}.state.expect >/dev/null || ret=1
done
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: common
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' errors on missing end date ($n)"
ret=0
ksr common -K ns1 request common.test >ksr.request.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: request requires an end date" ksr.request.out.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR in the common case ($n)"
ret=0
ksr common -K ns1 -i $now -e +1y request common.test >ksr.request.out.$n 2>&1 || ret=1
# Bundle 1: KSK + ZSK1
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat ns1/$key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 2: KSK + ZSK1 + ZSK2
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat ns1/$key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys common.test 1 2 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 3: KSK + ZSK2
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat ns1/$key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >>ksr.request.expect.$n
# Footer
cp ksr.request.expect.$n ksr.request.expect.base
grep ";; KeySigningRequest 1.0 generated at" ksr.request.out.$n >footer.$n || ret=1
cat footer.$n >>ksr.request.expect.$n
# Check if request output is the same as expected.
diff -w ksr.request.out.$n ksr.request.expect.$n >/dev/null || ret=1
# Save request for ksr sign operation.
cp ksr.request.expect.$n ksr.request.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: common
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' errors on missing KSR file ($n)"
ret=0
ksr common -K ns1 -i $now -e +1y sign common.test >ksr.sign.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: 'sign' requires a KSR file" ksr.sign.out.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR in the common case ($n)"
ret=0
ksr common -K ns1 -i $now -e +1y -K ns1/offline -f ksr.request.expect sign common.test >ksr.sign.out.$n 2>&1 || ret=1

_update_expected_zsks() {
  zsk=$((zsk + 1))
  next=$((next + 1))
  inception=$rollover_done
  if [ "$next" -le "$numzsks" ]; then
    key1="${zone}.${DEFAULT_ALGORITHM_NUMBER}.zsk${zsk}"
    key2="${zone}.${DEFAULT_ALGORITHM_NUMBER}.zsk${next}"
    zsk1=$(cat $key1.id)
    zsk2=$(cat $key2.id)
    rollover_start=$(cat ns1/$zsk2.state | grep "Published" | awk '{print $2}')
    rollover_done=$(cat ns1/$zsk1.state | grep "Removed" | awk '{print $2}')
  else
    # No more expected rollovers.
    key1="${zone}.${DEFAULT_ALGORITHM_NUMBER}.zsk${zsk}"
    zsk1=$(cat $key1.id)
    rollover_start=$((end + 1))
    rollover_done=$((end + 1))
  fi
}

check_skr() {
  _ret=0
  zone=$1
  dir=$2
  file=$3
  start=$4
  end=$5
  numzsks=$6
  cds1=$($DSFROMKEY -T 3600 -a SHA-1 -C -w $dir/$(cat "${zone}.ksk1.id"))
  cds2=$($DSFROMKEY -T 3600 -a SHA-256 -C -w $dir/$(cat "${zone}.ksk1.id"))
  cds4=$($DSFROMKEY -T 3600 -a SHA-384 -C -w $dir/$(cat "${zone}.ksk1.id"))
  cdnskey=$(awk '{sub(/DNSKEY/,"CDNSKEY")}1' <${zone}.ksk1)

  echo_i "check skr: zone $1 file $2 from $3 to $4 num-zsk $5"

  # Initial state: not in a rollover, expect a SignedKeyResponse header
  # on the first line, start with the first ZSK (set zsk=0 so when we
  # call _update_expected_zsks, zsk is set to 1.
  rollover=0
  expect="header"
  zsk=0
  next=1
  rollover_done=$start
  _update_expected_zsks

  echo_i "check skr: inception $inception rollover-start $rollover_start rollover-done $rollover_done"

  lineno=0
  complete=0
  while IFS= read -r line; do
    # A single signed key response may consist of:
    # ;; SignedKeyResponse (header)
    # ;; DNSKEY 257 (ksk)
    # ;; one or two (during rollover) DNSKEY 256 (zsk1, zsk2)
    # ;; RRSIG(DNSKEY) (rrsig-dnskey)
    # ;; CDNSKEY (cdnskey)
    # ;; RRSIG(CDNSKEY) (rrsig-cdnskey)
    # ;; CDS (cds)
    # ;; RRSIG(CDS) (rrsig-cds)
    err=0
    lineno=$((lineno + 1))

    # skip empty lines
    if [ -z "$line" ]; then
      continue
    fi

    if [ "$expect" = "header" ]; then
      expected=";; SignedKeyResponse 1.0 $inception"
      echo $line | grep "$expected" >/dev/null || err=1
      next_inception=$(addtime $inception 777600)
      expect="ksk"
    elif [ "$expect" = "ksk" ]; then
      expected="$(cat ${zone}.ksk1)"
      echo $line | grep "$expected" >/dev/null || err=1
      expect="zsk1"
    elif [ "$expect" = "cdnskey" ]; then
      expected="$cdnskey"
      echo $line | grep "$expected" >/dev/null || err=1
      expect="rrsig-cdnskey"
    elif [ "$expect" = "cds1" ]; then
      expected="$cds1"
      echo $line | grep "$expected" >/dev/null || err=1
      if [ "$CDS_SHA256" = "yes" ]; then
        expect="cds2"
      elif [ "$CDS_SHA384" = "yes" ]; then
        expect="cds4"
      else
        expect="rrsig-cds"
      fi
    elif [ "$expect" = "cds2" ]; then
      expected="$cds2"
      echo $line | grep "$expected" >/dev/null || err=1
      if [ "$CDS_SHA384" = "yes" ]; then
        expect="cds4"
      else
        expect="rrsig-cds"
      fi
    elif [ "$expect" = "cds4" ]; then
      expected="$cds4"
      echo $line | grep "$expected" >/dev/null || err=1
      expect="rrsig-cds"
    elif [ "$expect" = "zsk1" ]; then
      expected="$(cat $key1)"
      echo $line | grep "$expected" >/dev/null || err=1
      expect="rrsig-dnskey"
      [ "$rollover" -eq 1 ] && expect="zsk2"
    elif [ "$expect" = "zsk2" ]; then
      expected="$(cat $key2)"
      echo $line | grep "$expected" >/dev/null || err=1
      expect="rrsig-dnskey"
    elif [ "$expect" = "rrsig-dnskey" ]; then
      exp=$(addtime $inception 1209600) # signature-validity 14 days
      inc=$(addtime $inception -3600)   # adjust for one hour clock skew
      expected="${zone}. 3600 IN RRSIG DNSKEY 13 2 3600 $exp $inc"
      echo $line | grep "$expected" >/dev/null || err=1
      if [ "$CDNSKEY" = "yes" ]; then
        expect="cdnskey"
      elif [ "$CDS_SHA1" = "yes" ]; then
        expect="cds1"
      elif [ "$CDS_SHA256" = "yes" ]; then
        expect="cds2"
      elif [ "$CDS_SHA384" = "yes" ]; then
        expect="cds4"
      else
        complete=1
      fi
    elif [ "$expect" = "rrsig-cdnskey" ]; then
      exp=$(addtime $inception 1209600) # signature-validity 14 days
      inc=$(addtime $inception -3600)   # adjust for one hour clock skew
      expected="${zone}. 3600 IN RRSIG CDNSKEY 13 2 3600 $exp $inc"
      echo $line | grep "$expected" >/dev/null || err=1
      if [ "$CDS_SHA1" = "yes" ]; then
        expect="cds1"
      elif [ "$CDS_SHA256" = "yes" ]; then
        expect="cds2"
      elif [ "$CDS_SHA384" = "yes" ]; then
        expect="cds4"
      else
        complete=1
      fi
    elif [ "$expect" = "rrsig-cds" ]; then
      exp=$(addtime $inception 1209600) # signature-validity 14 days
      inc=$(addtime $inception -3600)   # adjust for one hour clock skew
      expected="${zone}. 3600 IN RRSIG CDS 13 2 3600 $exp $inc"
      echo $line | grep "$expected" >/dev/null || err=1
      complete=1
    elif [ "$expect" = "footer" ]; then
      expected=";; SignedKeyResponse 1.0 generated at"
      echo "$(echo $line | tr -s ' ')" | grep "$expected" >/dev/null || err=1

      expect="eof"
    elif [ "$expect" = "eof" ]; then
      expected="EOF"
      echo_i "failed: expected EOF"
      err=1
    else
      echo_i "failed: bad expect value $expect"
      err=1
    fi

    echo "$(echo $line | tr -s ' ')" | grep "$expected" >/dev/null || err=1
    if [ "$err" -ne 0 ]; then
      echo_i "unexpected data on line $lineno:"
      echo_i "line:     $(echo $line | tr -s ' ')"
      echo_i "expected: $expected"
    fi

    if [ "$complete" -eq 1 ]; then
      inception=$next_inception
      expect="header"

      # Update rollover status if required.
      if [ "$inception" -ge "$end" ]; then
        expect="footer"
      elif [ "$inception" -ge "$rollover_done" ]; then
        [ "$rollover" -eq 1 ] && inception=$rollover_done
        rollover=0
        _update_expected_zsks
      elif [ "$inception" -ge "$rollover_start" ]; then
        [ "$rollover" -eq 0 ] && inception=$rollover_start
        rollover=1
        # Keys will be sorted, so during a rollover a key with a
        # lower keytag will be printed first. Update key1/key2 and
        # zsk1/zsk2 accordingly.
        id1=$(keyfile_to_key_id "$zsk1")
        id2=$(keyfile_to_key_id "$zsk2")
        if [ $id1 -gt $id2 ]; then
          key1="${zone}.${DEFAULT_ALGORITHM_NUMBER}.zsk${next}"
          key2="${zone}.${DEFAULT_ALGORITHM_NUMBER}.zsk${zsk}"
          zsk1=$(cat $key1.id)
          zsk2=$(cat $key2.id)
        fi
      fi
      complete=0
    fi

    _ret=$((_ret + err))
    test "$_ret" -eq 0 || exit $_ret
  done <$file

  return $_ret
}

zsk1=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
start=$(cat ns1/$zsk1.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 31536000) # one year
check_skr "common.test" "ns1/offline" "ksr.sign.out.$n" $start $end 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Key generation: common (2)
n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' pregenerates keys in the given key-directory ($n)"
ret=0
ksr common -K ns1/keydir -e +1y keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
ksr_check_keys common.test ns1/keydir 0 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' selects generates only necessary keys for overlapping time bundle ($n)"
ret=0
ksr common -K ns1 -e +2y -v 1 keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
# 2 selected, 2 generated
num=$(grep "Selecting" ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
num=$(grep "Generating" ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "run 'dnssec-ksr keygen' again with verbosity 0 ($n)"
ret=0
ksr common -K ns1 -i $now -e +2y keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
ksr_check_keys common.test ns1 0 || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: common (2)
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR if the interval is shorter ($n)"
ret=0
ksr common -K ns1 -i $now -e +1y request common.test >ksr.request.out.$n 2>&1 || ret=1
# Same as earlier.
cp ksr.request.expect.base ksr.request.expect.$n
grep ";; KeySigningRequest 1.0 generated at" ksr.request.out.$n >footer.$n || ret=1
cat footer.$n >>ksr.request.expect.$n
diff -w ksr.request.out.$n ksr.request.expect.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with new interval ($n)"
ret=0
ksr common -K ns1 -i $now -e +2y request common.test >ksr.request.out.$n 2>&1 || ret=1
cp ksr.request.expect.base ksr.request.expect.$n
# Bundle 4: KSK + ZSK2 + ZSK3
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3.id)
inception=$(cat ns1/$key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys common.test 2 3 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 5: KSK + ZSK3
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat ns1/$key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3 >>ksr.request.expect.$n
# Bundle 6: KSK + ZSK3 + ZSK4
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk4.id)
inception=$(cat ns1/$key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys common.test 3 4 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 7: KSK + ZSK4
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3.id)
inception=$(cat ns1/$key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk4 >>ksr.request.expect.$n
# Footer
cp ksr.request.expect.$n ksr.request.expect.base
grep ";; KeySigningRequest 1.0 generated at" ksr.request.out.$n >footer.$n || ret=1
cat footer.$n >>ksr.request.expect.$n
diff -w ksr.request.out.$n ksr.request.expect.$n >/dev/null || ret=1
# Save request for ksr sign operation.
cp ksr.request.expect.$n ksr.request.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr request' errors if there are not enough keys ($n)"
ret=0
ksr common -K ns1 -i $now -e +3y request common.test >ksr.request.out.$n 2>ksr.request.err.$n && ret=1
grep "dnssec-ksr: fatal: no common.test/ECDSAP256SHA256 zsk key pair found for bundle" ksr.request.err.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: common (2)
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with the new interval ($n)"
ret=0
ksr common -K ns1 -i $now -e +2y -K ns1/offline -f ksr.request.expect sign common.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat ns1/$zsk1.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 63072000) # two years
check_skr "common.test" "ns1/offline" "ksr.sign.out.$n" $start $end 4 || ret=1
# Save response for skr import operation.
cp ksr.sign.out.$n ns1/common.test.skr
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Add zone: common
n=$((n + 1))
echo_i "add zone 'common.test' ($n)"
ret=0
$RNDCCMD 10.53.0.1 addzone 'common.test { type primary; file "common.test.db"; dnssec-policy common; };' 2>&1 | sed 's/^/I:ns1 /' || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Import skr: common
n=$((n + 1))
echo_i "import ksr to zone 'common.test' ($n)"
ret=0
sleep 2
$RNDCCMD 10.53.0.1 skr -import common.test.skr common.test 2>&1 | sed 's/^/I:ns1 /' || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Test that common.test is signed and uses the right DNSKEY and RRSIG records.
n=$((n + 1))
echo_i "test zone 'common.test' is correctly signed ($n)"
ret=0

set_zone "common.test"
set_policy "common" "4" "3600"
set_server "ns1" "10.53.0.1"
# Only ZSKs
set_keyrole "KEY1" "zsk"
set_keylifetime "KEY1" "16070400"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "no"
set_zonesigning "KEY1" "yes"
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"

set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "16070400"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "no"
set_keystate "KEY2" "GOAL" "hidden"
set_keystate "KEY2" "STATE_DNSKEY" "hidden"
set_keystate "KEY2" "STATE_ZRRSIG" "hidden"

set_keyrole "KEY3" "zsk"
set_keylifetime "KEY3" "16070400"
set_keyalgorithm "KEY3" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY3" "no"
set_zonesigning "KEY3" "no"
set_keystate "KEY3" "GOAL" "hidden"
set_keystate "KEY3" "STATE_DNSKEY" "hidden"
set_keystate "KEY3" "STATE_ZRRSIG" "hidden"

set_keyrole "KEY4" "zsk"
set_keylifetime "KEY4" "16070400"
set_keyalgorithm "KEY4" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY4" "no"
set_zonesigning "KEY4" "no"
set_keystate "KEY4" "GOAL" "hidden"
set_keystate "KEY4" "STATE_DNSKEY" "hidden"
set_keystate "KEY4" "STATE_ZRRSIG" "hidden"

MAXDEPTH=1
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_subdomain
dnssec_verify

# For checking the apex, we need to store the expected KSK metadata.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

set_policy "common" "1" "3600"
set_server "ns1/offline" "10.53.0.1"
set_keyrole "KEY2" "ksk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "no"
check_keys "keep"

DIR="ns1"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY2" "STATE_DS" "omnipresent"
check_apex

# Check that key id's match expected keys
n=$((n + 1))
zsk1=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
key1=$(key_get "KEY1" BASEFILE)
echo_i "check that published zsk $zsk1 matches first key $key1 in bundle ($n)"
ret=0
[ "ns1/$zsk1" = "$key1" ] || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
ksk=$(cat common.test.ksk1.id)
key2=$(key_get "KEY2" BASEFILE)
echo_i "check that published ksk $ksk matches ksk $key2 ($n)"
ret=0
[ "ns1/offline/$ksk" = "$key2" ] || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Key generation: last-bundle
n=$((n + 1))
echo_i "generate keys for testing an SKR that is in the last bundle ($n)"
ret=0
ksr common -K ns1 -i -1y -e +1d keygen last-bundle.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
ksr_check_keys last-bundle.test ns1 -31536000 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Create request: last-bundle
n=$((n + 1))
echo_i "create ksr for last bundle test ($n)"
ret=0
ksr common -K ns1 -i -1y -e +1d request last-bundle.test >ksr.request.out.$n 2>&1 || ret=1
cp ksr.request.out.$n last-bundle.test.ksr
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Sign request: last-bundle
n=$((n + 1))
echo_i "create skr for last bundle test ($n)"
ret=0
ksr common -i -1y -e +1d -K ns1/offline -f last-bundle.test.ksr sign last-bundle.test >ksr.sign.out.$n 2>&1 || ret=1
cp ksr.sign.out.$n ns1/last-bundle.test.skr
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Add zone: last-bundle
n=$((n + 1))
echo_i "add zone 'last-bundle.test' ($n)"
ret=0
$RNDCCMD 10.53.0.1 addzone 'last-bundle.test { type primary; file "last-bundle.test.db"; dnssec-policy common; };' 2>&1 | sed 's/^/I:ns1 /' || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Import skr: last-bundle
n=$((n + 1))
echo_i "import ksr to zone 'last-bundle.test' ($n)"
ret=0
sleep 2
$RNDCCMD 10.53.0.1 skr -import last-bundle.test.skr last-bundle.test 2>&1 | sed 's/^/I:ns1 /' || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Test that last-bundle.test is signed and uses the right DNSKEY and RRSIG records.
n=$((n + 1))
echo_i "test zone 'last-bundle.test' is correctly signed ($n)"
ret=0

set_zone "last-bundle.test"
set_policy "common" "2" "3600"
set_server "ns1" "10.53.0.1"
# Only ZSKs
key_clear "KEY1"
set_keyrole "KEY1" "zsk"
set_keylifetime "KEY1" "16070400"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "no"
set_zonesigning "KEY1" "yes"
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "16070400"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "no"
set_keystate "KEY2" "GOAL" "hidden"
set_keystate "KEY2" "STATE_DNSKEY" "hidden"
set_keystate "KEY2" "STATE_ZRRSIG" "hidden"

MAXDEPTH=1
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_subdomain
dnssec_verify

# For checking the apex, we need to store the expected KSK metadata.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

set_policy "common" "1" "3600"
set_server "ns1/offline" "10.53.0.1"
set_keyrole "KEY2" "ksk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "no"
check_keys "keep"

DIR="ns1"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY2" "STATE_DS" "omnipresent"
check_apex

# Check that key id's match expected keys
n=$((n + 1))
zsk2=$(cat last-bundle.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
key1=$(key_get "KEY1" BASEFILE)
echo_i "check that published zsk $zsk2 matches first key $key1 in bundle ($n)"
ret=0
[ "ns1/$zsk2" = "$key1" ] || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
ksk=$(cat last-bundle.test.ksk1.id)
key2=$(key_get "KEY2" BASEFILE)
echo_i "check that published ksk $ksk matches ksk $key2 ($n)"
ret=0
[ "ns1/offline/$ksk" = "$key2" ] || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that last bundle warning is logged ($n)"
wait_for_log 3 "zone last-bundle.test/IN (signed): zone_rekey: last bundle in skr, please import new skr file" ns1/named.run || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Key generation: in-the-middle
n=$((n + 1))
echo_i "generate keys for testing an SKR that is in the middle ($n)"
ret=0
ksr common -K ns1 -i -1y -e +1y keygen in-the-middle.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
ksr_check_keys in-the-middle.test ns1 -31536000 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Create request: in-the-middle
n=$((n + 1))
echo_i "create ksr for in the middle test ($n)"
ret=0
ksr common -K ns1 -i -1y -e +1y request in-the-middle.test >ksr.request.out.$n 2>&1 || ret=1
cp ksr.request.out.$n in-the-middle.test.ksr
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Sign request: in-the-middle
n=$((n + 1))
echo_i "create skr for in the middle test ($n)"
ret=0
ksr common -i -1y -e +1y -K ns1/offline -f in-the-middle.test.ksr sign in-the-middle.test >ksr.sign.out.$n 2>&1 || ret=1
cp ksr.sign.out.$n ns1/in-the-middle.test.skr
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Add zone: in-the-middle
n=$((n + 1))
echo_i "add zone 'in-the-middle.test' ($n)"
ret=0
$RNDCCMD 10.53.0.1 addzone 'in-the-middle.test { type primary; file "in-the-middle.test.db"; dnssec-policy common; };' 2>&1 | sed 's/^/I:ns1 /' || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Import skr: in-the-middle
n=$((n + 1))
echo_i "import ksr to zone 'in-the-middle.test' ($n)"
ret=0
sleep 2
$RNDCCMD 10.53.0.1 skr -import in-the-middle.test.skr in-the-middle.test 2>&1 | sed 's/^/I:ns1 /' || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Test that in-the-middle.test is signed and uses the right DNSKEY and RRSIG records.
n=$((n + 1))
echo_i "test zone 'in-the-middle.test' is correctly signed ($n)"
ret=0

set_zone "in-the-middle.test"
set_policy "common" "4" "3600"
set_server "ns1" "10.53.0.1"
# Only ZSKs
key_clear "KEY1"
set_keyrole "KEY1" "zsk"
set_keylifetime "KEY1" "16070400"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "no"
set_zonesigning "KEY1" "yes"
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "16070400"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "no"
set_keystate "KEY2" "GOAL" "hidden"
set_keystate "KEY2" "STATE_DNSKEY" "hidden"
set_keystate "KEY2" "STATE_ZRRSIG" "hidden"

key_clear "KEY3"
set_keyrole "KEY3" "zsk"
set_keylifetime "KEY3" "16070400"
set_keyalgorithm "KEY3" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY3" "no"
set_zonesigning "KEY3" "no"
set_keystate "KEY3" "GOAL" "hidden"
set_keystate "KEY3" "STATE_DNSKEY" "hidden"
set_keystate "KEY3" "STATE_ZRRSIG" "hidden"

key_clear "KEY4"
set_keyrole "KEY4" "zsk"
set_keylifetime "KEY4" "16070400"
set_keyalgorithm "KEY4" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY4" "no"
set_zonesigning "KEY4" "no"
set_keystate "KEY4" "GOAL" "hidden"
set_keystate "KEY4" "STATE_DNSKEY" "hidden"
set_keystate "KEY4" "STATE_ZRRSIG" "hidden"

MAXDEPTH=1
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_subdomain
dnssec_verify

# For checking the apex, we need to store the expected KSK metadata.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

set_policy "common" "1" "3600"
set_server "ns1/offline" "10.53.0.1"
set_keyrole "KEY2" "ksk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "no"
check_keys "keep"

DIR="ns1"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY2" "STATE_DS" "omnipresent"
check_apex

# Check that key id's match expected keys
n=$((n + 1))
zsk2=$(cat in-the-middle.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
key1=$(key_get "KEY1" BASEFILE)
echo_i "check that published zsk $zsk2 matches first key $key1 in bundle ($n)"
ret=0
[ "ns1/$zsk2" = "$key1" ] || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
ksk=$(cat in-the-middle.test.ksk1.id)
key2=$(key_get "KEY2" BASEFILE)
echo_i "check that published ksk $ksk matches ksk $key2 ($n)"
ret=0
[ "ns1/offline/$ksk" = "$key2" ] || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that no last bundle warning is logged ($n)"
grep "zone $zone/IN (signed): zone_rekey failure: no available SKR bundle" ns1/named.run && ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Test error conditions
check_rekey_logs_error() {
  zone=$1
  inc=$2
  exp=$3
  offset=$4

  # Key generation
  ksr common -K ns1 -i $inc -e $exp keygen $zone >ksr.keygen.out.$n 2>&1 || return 1
  num=$(cat ksr.keygen.out.$n | wc -l)
  [ $num -eq 2 ] || return 1
  set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
  ksr_check_keys $zone ns1 $offset || return 1
  # Create request
  ksr common -K ns1 -i $inc -e $exp request $zone >ksr.request.out.$n 2>&1 || return 1
  cp ksr.request.out.$n $zone.ksr
  # Sign request
  ksr common -K ns1/offline -i $inc -e $exp -f $zone.ksr sign $zone >ksr.sign.out.$n 2>&1 || return 1
  cp ksr.sign.out.$n ns1/$zone.skr
  # Import skr
  $RNDCCMD 10.53.0.1 skr -import $zone.skr $zone 2>&1 | sed 's/^/I:ns1 /' || return 1
  # Test that rekey logs error
  wait_for_log 3 "zone $zone/IN (signed): zone_rekey failure: no available SKR bundle" ns1/named.run || return 1
}

n=$((n + 1))
echo_i "check that an SKR that is too old logs error ($n)"
$RNDCCMD 10.53.0.1 addzone 'past.test { type primary; file "past.test.db"; dnssec-policy common; };' 2>&1 | sed 's/^/I:ns1 /' || ret=1
check_rekey_logs_error "past.test" -2y -1y -63072000 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that an SKR that is too new logs error ($n)"
$RNDCCMD 10.53.0.1 addzone 'future.test { type primary; file "future.test.db"; dnssec-policy common; };' 2>&1 | sed 's/^/I:ns1 /' || ret=1
check_rekey_logs_error "future.test" +1mo +1y 2592000 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Key generation: csk
n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' creates no keys for policy with csk ($n)"
ret=0
ksr csk -e +2y keygen csk.test >ksr.keygen.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: policy 'csk' has no zsks" ksr.keygen.out.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Key generation: unlimited
n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' creates only one key for zsk with unlimited lifetime ($n)"
ret=0
ksr unlimited -K ns1 -e +2y keygen unlimited.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 1 ] || ret=1
key=$(cat ksr.keygen.out.$n)
grep "; Created:" "ns1/${key}.key" >created.out || ret=1
created=$(awk '{print $3}' <created.out)
active=$created
published=$(addtime $active -7500)
echo_i "check metadata on $key"
grep "Algorithm: $DEFAULT_ALGORITHM_NUMBER" ns1/${key}.state >/dev/null || ret=1
grep "Length: $DEFAULT_BITS" ns1/${key}.state >/dev/null || ret=1
grep "Lifetime: 0" ns1/${key}.state >/dev/null || ret=1
grep "KSK: no" ns1/${key}.state >/dev/null || ret=1
grep "ZSK: yes" ns1/${key}.state >/dev/null || ret=1
grep "Published: $published" ns1/${key}.state >/dev/null || ret=1
grep "Active: $active" ns1/${key}.state >/dev/null || ret=1
grep "Retired:" ns1/${key}.state >/dev/null && ret=1
grep "Removed:" ns1/${key}.state >/dev/null && ret=1
cat ns1/${key}.key | grep -v ";.*" >unlimited.test.$DEFAULT_ALGORITHM_NUMBER.zsk1
echo $key >"unlimited.test.${DEFAULT_ALGORITHM_NUMBER}.zsk1.id"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: unlimited
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with unlimited zsk ($n)"
ret=0
ksr unlimited -K ns1 -i $created -e +4y request unlimited.test >ksr.request.out.$n 2>&1 || ret=1
# Only one bundle: KSK + ZSK
inception=$(cat ns1/$key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >ksr.request.expect.$n
cat unlimited.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Footer
grep ";; KeySigningRequest 1.0 generated at" ksr.request.out.$n >footer.$n || ret=1
cat footer.$n >>ksr.request.expect.$n
diff -w ksr.request.out.$n ksr.request.expect.$n >/dev/null || ret=1
# Save request for ksr sign operation.
cp ksr.request.expect.$n ksr.request.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: unlimited
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with unlimited zsk ($n)"
ret=0
ksr unlimited -K ns1 -i $created -e +4y -K ns1/offline -f ksr.request.expect sign unlimited.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat ns1/$key.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 126144000) # four years
check_skr "unlimited.test" "ns1/offline" "ksr.sign.out.$n" $start $end 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: unlimited (no-cdnskey)
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with unlimited zsk, no cdnskey ($n)"
ret=0
ksr no-cdnskey -K ns1 -i $created -e +4y -K ns1/offline -f ksr.request.expect sign unlimited.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat ns1/$key.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 126144000) # four years
CDNSKEY="no"
CDS_SHA1="yes"
CDS_SHA256="yes"
CDS_SHA384="yes"
check_skr "unlimited.test" "ns1/offline" "ksr.sign.out.$n" $start $end 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: unlimited (no-cds)
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with unlimited zsk, no cds ($n)"
ret=0
ksr no-cds -K ns1 -i $created -e +4y -K ns1/offline -f ksr.request.expect sign unlimited.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat ns1/$key.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 126144000) # four years
CDNSKEY="yes"
CDS_SHA1="no"
CDS_SHA256="no"
CDS_SHA384="no"
check_skr "unlimited.test" "ns1/offline" "ksr.sign.out.$n" $start $end 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Reset CDS and CDNSKEY to default values
CDNSKEY="yes"
CDS_SHA1="no"
CDS_SHA256="yes"
CDS_SHA384="no"

# Key generation: two-tone
n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' creates keys for different algorithms ($n)"
ret=0
ksr two-tone -K ns1 -e +1y keygen two-tone.test >ksr.keygen.out.$n 2>&1 || ret=1
# First algorithm keys have a lifetime of 3 months, so there should be 4 created keys.
alg=$(printf "%03d" "$DEFAULT_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 8035200
ksr_check_keys two-tone.test ns1 0 || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect.$DEFAULT_ALGORITHM_NUMBER
# Second algorithm keys have a lifetime of 5 months, so there should be 3 created keys.
# While only two time bundles of 5 months fit into one year, we need to create an
# extra key for the remainder of the bundle.
alg=$(printf "%03d" "$ALTERNATIVE_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.keygen.out.$n | wc -l)
[ $num -eq 3 ] || ret=1
set_zsk $ALTERNATIVE_ALGORITHM_NUMBER $ALTERNATIVE_BITS 13392000
ksr_check_keys two-tone.test ns1 0 || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect.$ALTERNATIVE_ALGORITHM_NUMBER
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: two-tone
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with multiple algorithms ($n)"
ret=0
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
grep "; Created:" "ns1/${key}.key" >created.out || ret=1
created=$(awk '{print $3}' <created.out)
ksr two-tone -K ns1 -i $created -e +6mo request two-tone.test >ksr.request.out.$n 2>&1 || ret=1
# The two-tone policy uses two sets of KSK/ZSK with different algorithms. One
# set uses the default algorithm (denoted as A below), the other is using the
# alternative algorithm (denoted as B). The A-ZSKs roll every three months,
# so in the second bundle there should be a new DNSKEY prepublished, and the
# predecessor is removed in the third bundle. Then, after five months the
# ZSK for the B set is rolled, adding the successor in bundle 4 and removing
# its predecessor in bundle 5.
#
# Bundle 1: KSK-A1, KSK-B1, ZSK-A1, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat ns1/$key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 2: KSK-A1, KSK-B1, ZSK-A1 + ZSK-A2, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat ns1/$key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys two-tone.test 1 2 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect.$DEFAULT_ALGORITHM_NUMBER >>ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 3: KSK-A1, KSK-B1, ZSK-A2, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat ns1/$key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >>ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 4: KSK-A1, KSK-B1, ZSK-A2, ZSK-B1 + ZSK-B2
key=$(cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat ns1/$key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >>ksr.request.expect.$n
print_dnskeys two-tone.test 1 2 $ALTERNATIVE_ALGORITHM_NUMBER ksr.keygen.out.expect.$ALTERNATIVE_ALGORITHM_NUMBER >>ksr.request.expect.$n
# Bundle 5: KSK-A1, KSK-B1, ZSK-A2, ZSK-B2
key=$(cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat ns1/$key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >>ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk2 >>ksr.request.expect.$n
# Footer
grep ";; KeySigningRequest 1.0 generated at" ksr.request.out.$n >footer.$n || ret=1
cat footer.$n >>ksr.request.expect.$n
# Check the KSR request against the expected request.
diff -w ksr.request.out.$n ksr.request.expect.$n >/dev/null || ret=1
# Save request for ksr sign operation.
cp ksr.request.expect.$n ksr.request.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

num_occurrences() {
  count="$1"
  file="$2"
  line="$3"
  exclude="$4"

  if [ -z "$exclude" ]; then
    lines=$(cat "$file" | while read line; do echo $line; done | grep "$line" | wc -l)
    echo_i "$lines occurrences: $1 $2 $3"
  else
    lines=$(cat "$file" | while read line; do echo $line; done | grep -v "$exclude" | grep "$line" | wc -l)
    echo_i "$lines occurrences: $1 $2 $3 (exclude $4)"
  fi

  test "$lines" -eq "$count" || return 1
}

# Sign request: two-tone
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with multiple algorithms ($n)"
ret=0
ksr two-tone -i $created -e +6mo -K ns1/offline -f ksr.request.expect sign two-tone.test >ksr.sign.out.$n 2>&1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
# Weak testing:
zone="two-tone.test"
# expect 24 headers (including the footer)
num_occurrences 24 ksr.sign.out.$n ";; SignedKeyResponse 1.0" || ret=1
# expect 23 KSKs and its signatures (for each header one)
num_occurrences 23 ksr.sign.out.$n "DNSKEY 257 3 8" "CDNSKEY" || ret=1 # exclude CDNSKEY lines
test "$ret" -eq 0 || echo_i "2 failed"
num_occurrences 23 ksr.sign.out.$n "DNSKEY 257 3 13" "CDNSKEY" || ret=1 # exclude CDNSKEY lines
test "$ret" -eq 0 || echo_i "3 failed"
num_occurrences 23 ksr.sign.out.$n "RRSIG DNSKEY 8" "CDNSKEY" || ret=1 # exclude CDNSKEY lines
test "$ret" -eq 0 || echo_i "4 failed"
num_occurrences 23 ksr.sign.out.$n "RRSIG DNSKEY 13" "CDNSKEY" || ret=1 # exclude CDNSKEY lines
test "$ret" -eq 0 || echo_i "5 failed"
# ... 23 CDNSKEY records and its signatures
num_occurrences 23 ksr.sign.out.$n "CDNSKEY 257 3 8" || ret=1
test "$ret" -eq 0 || echo_i "6 failed"
num_occurrences 23 ksr.sign.out.$n "CDNSKEY 257 3 13" || ret=1
test "$ret" -eq 0 || echo_i "7 failed"
num_occurrences 23 ksr.sign.out.$n "RRSIG CDNSKEY 8" || ret=1
test "$ret" -eq 0 || echo_i "8 failed"
num_occurrences 23 ksr.sign.out.$n "RRSIG CDNSKEY 13" || ret=1
test "$ret" -eq 0 || echo_i "9 failed"
# ... 23 CDS records and its signatures
num_occurrences 23 ksr.sign.out.$n "CDS 8 2" || ret=1
test "$ret" -eq 0 || echo_i "10 failed"
num_occurrences 23 ksr.sign.out.$n "CDS 13 2" || ret=1
test "$ret" -eq 0 || echo_i "11 failed"
num_occurrences 23 ksr.sign.out.$n "RRSIG CDS 8" || ret=1
test "$ret" -eq 0 || echo_i "12 failed"
num_occurrences 23 ksr.sign.out.$n "RRSIG CDS 13" || ret=1
test "$ret" -eq 0 || echo_i "13 failed"
# expect 25 ZSK (two more for double keys during the rollover)
num_occurrences 25 ksr.sign.out.$n "DNSKEY 256 3 8" || ret=1
test "$ret" -eq 0 || echo_i "14 failed"
num_occurrences 25 ksr.sign.out.$n "DNSKEY 256 3 13" || ret=1
test "$ret" -eq 0 || echo_i "15 failed"
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
