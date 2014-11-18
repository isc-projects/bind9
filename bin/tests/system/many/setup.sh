# Copyright (C) 2014  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

i=1

cat > ns3/root.db << EOF
. 60 in soa ns.nil. hostmaster.ns.nil. 1 0 0 0 0
. 60 in ns ns.nil.
ns.nil. 60 in a 10.53.0.3
tld1. 60 in ns ns.tld1.
ns.tld1. 60 in a 10.53.0.3
tld2. 60 in ns ns.tld2.
ns.tld2. 60 in a 10.53.0.4
EOF

cat > ns3/tld1.db << EOF
tld1. 60 in soa ns.tld1. hostmaster.ns.tld1. 1 0 0 0 0
tld1. 60 in ns ns.tld1.
ns.tld1. 60 in a 10.53.0.1
EOF

cat > ns4/tld2.db << EOF
tld2. 60 in soa ns.tld2. hostmaster.ns.tld4. 1 0 0 0 0
tld2. 60 in ns ns.tld2.
ns.tld2. 60 in a 10.53.0.1
EOF

: > ns1/zones.conf
: > ns2/zones.conf

while [ $i -lt 1000 ]
do
j=`expr $i + 1`
s=`expr $j % 2 + 1`
n=`expr $i % 2 + 1`
t=`expr $s + 2`

# i=1 j=2 s=1 n=2
# i=2 j=3 s=1 n=2
# i=3 j=4 s=1 n=2

cat > ns1/${i}example.tld${s}.db << EOF
${i}example.tld${s}. 60 in soa ns.${j}example.tld${n}. hostmaster 1 0 0 0 0
${i}example.tld${s}. 60 in ns ns.${j}example.tld${n}.
ns.${i}example.tld${s}. 60 in a 10.53.0.1
EOF

cat >> ns1/zones.conf << EOF
zone "${i}example.tld${s}" { type master; file "${i}example.tld${s}.db"; };
EOF

cat >> ns${t}/tld${s}.db << EOF
${i}example.tld${s}. 60 in ns ns.${j}example.tld${n}.
EOF

i=$j

done

j=`expr $i + 1`
s=`expr $j % 2 + 1`
n=`expr $s % 2 + 1`
t=`expr $s + 2`

cat > ns1/${i}example.tld${s}.db << EOF
${i}example.tld${s}. 60 in soa ns.${i}example.tld${s}. hostmaster 1 0 0 0 0
${i}example.tld${s}. 60 in ns ns.${i}example.tld${s}.
ns.${i}example.tld${s}. 60 in a 10.53.0.1
EOF

cat >> ns1/zones.conf << EOF
zone "${i}example.tld${s}" { type master; file "${i}example.tld${s}.db"; };
EOF

cat >> ns${t}/tld${s}.db << EOF
${i}example.tld${s}. 60 in ns ns.${i}example.tld${s}.
ns.${i}example.tld${s}. 60 in a 10.53.0.1
EOF
