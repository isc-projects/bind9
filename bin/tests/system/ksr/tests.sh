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
check_keys() (
  zone=$1
  dir=$2
  lifetime=$LIFETIME
  alg=$ALG
  size=$SIZE
  inception=0
  pad=$(printf "%03d" "$alg")

  num=0
  for key in $(grep "K${zone}.+$pad+" ksr.keygen.out.$n); do
    grep "; Created:" "${dir}/${key}.key" >created.out || return 1
    created=$(awk '{print $3}' <created.out)
    test "$num" -eq 0 && retired=$created
    # active: retired previous key
    active=$retired
    # published: 2h5m (dnskey-ttl + publish-safety + propagation)
    published=$(addtime $active -7500)
    # retired: zsk-lifetime
    retired=$(addtime $active $lifetime)
    # removed: 10d1h5m (ttlsig + retire-safety + sign-delay + propagation)
    removed=$(addtime $retired 867900)

    echo_i "check metadata on $key"
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
  $KSR -l named.conf -k "$@"
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
ksr common -i now -e +1y keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys common.test "." || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# save now time
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
grep "; Created:" "${key}.key" >now.out || ret=1
now=$(awk '{print $3}' <now.out)

n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' selects pregenerated keys for the same time bundle ($n)"
ret=0
ksr common -e +1y keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
diff -w ksr.keygen.out.expect ksr.keygen.out.$n >/dev/null || ret=1
for key in $(cat ksr.keygen.out.$n); do
  # Ensure the files are not modified.
  diff ${key}.key ${key}.key.expect >/dev/null || ret=1
  diff ${key}.private ${key}.private.expect >/dev/null || ret=1
  diff ${key}.state ${key}.state.expect >/dev/null || ret=1
done
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: common
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' errors on missing end date ($n)"
ret=0
ksr common request common.test >ksr.request.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: request requires an end date" ksr.request.out.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR in the common case ($n)"
ret=0
ksr common -i $now -e +1y request common.test >ksr.request.out.$n 2>&1 || ret=1
# Bundle 1: KSK + ZSK1
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 2: KSK + ZSK1 + ZSK2
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys common.test 1 2 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 3: KSK + ZSK2
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
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
ksr common -i $now -e +1y sign common.test >ksr.sign.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: 'sign' requires a KSR file" ksr.sign.out.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR in the common case ($n)"
ret=0
ksr common -i $now -e +1y -K offline -f ksr.request.expect sign common.test >ksr.sign.out.$n 2>&1 || ret=1

_update_expected_zsks() {
  zsk=$((zsk + 1))
  next=$((next + 1))
  inception=$rollover_done
  if [ "$next" -le "$numzsks" ]; then
    key1="${zone}.${DEFAULT_ALGORITHM_NUMBER}.zsk${zsk}"
    key2="${zone}.${DEFAULT_ALGORITHM_NUMBER}.zsk${next}"
    zsk1=$(cat $key1.id)
    zsk2=$(cat $key2.id)
    rollover_start=$(cat $zsk2.state | grep "Published" | awk '{print $2}')
    rollover_done=$(cat $zsk1.state | grep "Removed" | awk '{print $2}')
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
  file=$2
  start=$3
  end=$4
  numzsks=$5
  cds1=$($DSFROMKEY -T 3600 -a SHA-1 -C -w $(cat "${zone}.ksk1.id"))
  cds2=$($DSFROMKEY -T 3600 -a SHA-256 -C -w $(cat "${zone}.ksk1.id"))
  cds4=$($DSFROMKEY -T 3600 -a SHA-384 -C -w $(cat "${zone}.ksk1.id"))
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
start=$(cat $zsk1.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 31536000) # one year
check_skr "common.test" "ksr.sign.out.$n" $start $end 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Key generation: common (2)
n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' pregenerates keys in the given key-directory ($n)"
ret=0
ksr common -e +1y -K keydir keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys common.test keydir || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "check that 'dnssec-ksr keygen' selects generates only necessary keys for overlapping time bundle ($n)"
ret=0
ksr common -e +2y -v 1 keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
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
ksr common -i $now -e +2y keygen common.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys common.test "." || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: common (2)
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR if the interval is shorter ($n)"
ret=0
ksr common -i $now -e +1y request common.test >ksr.request.out.$n 2>&1 || ret=1
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
ksr common -i $now -e +2y request common.test >ksr.request.out.$n 2>&1 || ret=1
cp ksr.request.expect.base ksr.request.expect.$n
# Bundle 4: KSK + ZSK2 + ZSK3
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys common.test 2 3 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 5: KSK + ZSK3
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3 >>ksr.request.expect.$n
# Bundle 6: KSK + ZSK3 + ZSK4
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk4.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys common.test 3 4 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 7: KSK + ZSK4
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
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
ksr common -i $now -e +3y request common.test >ksr.request.out.$n 2>ksr.request.err.$n && ret=1
grep "dnssec-ksr: fatal: no common.test/ECDSAP256SHA256 zsk key pair found for bundle" ksr.request.err.$n >/dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: common (2)
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with the new interval ($n)"
ret=0
ksr common -i $now -e +2y -K offline -f ksr.request.expect sign common.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat $zsk1.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 63072000) # two years
check_skr "common.test" "ksr.sign.out.$n" $start $end 4 || ret=1
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
ksr unlimited -e +2y keygen unlimited.test >ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 1 ] || ret=1
key=$(cat ksr.keygen.out.$n)
grep "; Created:" "${key}.key" >created.out || ret=1
created=$(awk '{print $3}' <created.out)
active=$created
published=$(addtime $active -7500)
echo_i "check metadata on $key"
grep "Algorithm: $DEFAULT_ALGORITHM_NUMBER" ${key}.state >/dev/null || ret=1
grep "Length: $DEFAULT_BITS" ${key}.state >/dev/null || ret=1
grep "Lifetime: 0" ${key}.state >/dev/null || ret=1
grep "KSK: no" ${key}.state >/dev/null || ret=1
grep "ZSK: yes" ${key}.state >/dev/null || ret=1
grep "Published: $published" ${key}.state >/dev/null || ret=1
grep "Active: $active" ${key}.state >/dev/null || ret=1
grep "Retired:" ${key}.state >/dev/null && ret=1
grep "Removed:" ${key}.state >/dev/null && ret=1
cat ${key}.key | grep -v ";.*" >unlimited.test.$DEFAULT_ALGORITHM_NUMBER.zsk1
echo $key >"unlimited.test.${DEFAULT_ALGORITHM_NUMBER}.zsk1.id"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: unlimited
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with unlimited zsk ($n)"
ret=0
ksr unlimited -i $created -e +4y request unlimited.test >ksr.request.out.$n 2>&1 || ret=1
# Only one bundle: KSK + ZSK
inception=$(cat $key.state | grep "Generated" | cut -d' ' -f 2-)
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
ksr unlimited -i $created -e +4y -K offline -f ksr.request.expect sign unlimited.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat $key.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 126144000) # four years
check_skr "unlimited.test" "ksr.sign.out.$n" $start $end 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: unlimited (no-cdnskey)
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with unlimited zsk, no cdnskey ($n)"
ret=0
ksr no-cdnskey -i $created -e +4y -K offline -f ksr.request.expect sign unlimited.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat $key.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 126144000) # four years
CDNSKEY="no"
CDS_SHA1="yes"
CDS_SHA256="yes"
CDS_SHA384="yes"
check_skr "unlimited.test" "ksr.sign.out.$n" $start $end 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Sign request: unlimited (no-cds)
n=$((n + 1))
echo_i "check that 'dnssec-ksr sign' creates correct SKR with unlimited zsk, no cds ($n)"
ret=0
ksr no-cds -i $created -e +4y -K offline -f ksr.request.expect sign unlimited.test >ksr.sign.out.$n 2>&1 || ret=1
start=$(cat $key.state | grep "Generated" | awk '{print $2}')
end=$(addtime $start 126144000) # four years
CDNSKEY="yes"
CDS_SHA1="no"
CDS_SHA256="no"
CDS_SHA384="no"
check_skr "unlimited.test" "ksr.sign.out.$n" $start $end 1 || ret=1
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
ksr two-tone -e +1y keygen two-tone.test >ksr.keygen.out.$n 2>&1 || ret=1
# First algorithm keys have a lifetime of 3 months, so there should be 4 created keys.
alg=$(printf "%03d" "$DEFAULT_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 8035200
check_keys two-tone.test "." || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect.$DEFAULT_ALGORITHM_NUMBER
# Second algorithm keys have a lifetime of 5 months, so there should be 3 created keys.
# While only two time bundles of 5 months fit into one year, we need to create an
# extra key for the remainder of the bundle.
alg=$(printf "%03d" "$ALTERNATIVE_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.keygen.out.$n | wc -l)
[ $num -eq 3 ] || ret=1
set_zsk $ALTERNATIVE_ALGORITHM_NUMBER $ALTERNATIVE_BITS 13392000
check_keys two-tone.test "." $ALTERNATIVE_ALGORITHM_NUMBER 13392000 || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect.$ALTERNATIVE_ALGORITHM_NUMBER
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Create request: two-tone
n=$((n + 1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with multiple algorithms ($n)"
ret=0
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
grep "; Created:" "${key}.key" >created.out || ret=1
created=$(awk '{print $3}' <created.out)
ksr two-tone -i $created -e +6mo request two-tone.test >ksr.request.out.$n 2>&1 || ret=1
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
inception=$(cat $key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 2: KSK-A1, KSK-B1, ZSK-A1 + ZSK-A2, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
print_dnskeys two-tone.test 1 2 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect.$DEFAULT_ALGORITHM_NUMBER >>ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 3: KSK-A1, KSK-B1, ZSK-A2, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >>ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >>ksr.request.expect.$n
# Bundle 4: KSK-A1, KSK-B1, ZSK-A2, ZSK-B1 + ZSK-B2
key=$(cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KeySigningRequest 1.0 $inception" >>ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >>ksr.request.expect.$n
print_dnskeys two-tone.test 1 2 $ALTERNATIVE_ALGORITHM_NUMBER ksr.keygen.out.expect.$ALTERNATIVE_ALGORITHM_NUMBER >>ksr.request.expect.$n
# Bundle 5: KSK-A1, KSK-B1, ZSK-A2, ZSK-B2
key=$(cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
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
ksr two-tone -i $created -e +6mo -K offline -f ksr.request.expect sign two-tone.test >ksr.sign.out.$n 2>&1 || ret=1
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
