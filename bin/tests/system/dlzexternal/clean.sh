#!/bin/sh
#
# Clean up after dlzexternal tests.
#

rm -f ns1/update.txt
rm -f */named.memstats
rm -f */named.conf
rm -f */named.run
rm -f ns1/ddns.key
