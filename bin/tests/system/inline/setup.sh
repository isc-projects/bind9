# Copyright (C) 2011  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: setup.sh,v 1.6 2011/12/09 13:32:42 marka Exp $

sh clean.sh

cp ns1/root.db.in ns1/root.db
rm -f ns1/root.db.signed

touch ns2/trusted.conf
cp ns2/bits.db.in ns2/bits.db
rm -f ns2/bits.db.jnl

rm -f ns3/bits.bk
rm -f ns3/bits.bk.jnl
rm -f ns3/bits.bk.signed
rm -f ns3/bits.bk.signed.jnl

rm -f ns3/noixfr.bk
rm -f ns3/noixfr.bk.jnl
rm -f ns3/noixfr.bk.signed
rm -f ns3/noixfr.bk.signed.jnl

rm -f ns3/master.db
rm -f ns3/master.db.jnl
rm -f ns3/master.db.signed
rm -f ns3/master.db.signed.jnl

rm -f ns3/dynamic.db
rm -f ns3/dynamic.db.jnl
rm -f ns3/dynamic.db.signed
rm -f ns3/dynamic.db.signed.jnl

cp ns3/master.db.in ns3/master.db
cp ns3/master.db.in ns3/dynamic.db

touch ns4/trusted.conf
cp ns4/noixfr.db.in ns4/noixfr.db
rm -f ns4/noixfr.db.jnl
rm -f ns?/*.pvt

cp ns5/named.conf.pre ns5/named.conf

../../../tools/genrandom 400 random.data

(cd ns3; sh -e sign.sh)
(cd ns1; sh -e sign.sh)
