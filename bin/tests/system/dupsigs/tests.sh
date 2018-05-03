SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

start=`date +%s`
end=`expr $start + 1200`
now=$start
while test $now -lt $end
do
	echo "=============== " `expr $now - $start` " ============"
	$JOURNALPRINT ns1/signing.test.db.signed.jnl | $PERL check_journal.pl
	$DIG axfr signing.test -p 5300 @10.53.0.1 | awk '$4 == "RRSIG" { print $11 }' | sort | uniq -c
	sleep 20
	now=`date +%s`
done
