sh clean.sh

touch ns2/trusted.conf
cp ns2/bits.db.in ns2/bits.db
rm -f ns2/bits.db.jnl

rm -f ns3/bits.bk
rm -f ns3/bits.bk.jnl
rm -f ns3/bits.bk.signed
rm -f ns3/bits.bk.signed.jnl

touch ns4/trusted.conf
cp ns4/noixfr.db.in ns4/noixfr.db
rm -f ns4/noixfr.db.jnl

rm -f ns3/noixfr.bk
rm -f ns3/noixfr.bk.jnl
rm -f ns3/noixfr.bk.signed
rm -f ns3/noixfr.bk.signed.jnl

../../../tools/genrandom 400 random.data

(cd ns3; sh -e sign.sh)
