#!/bin/sh
#
# Clean up after zone transfer quota tests.
#

rm -f ns1/zone*.example.db ns1/zones.conf
rm -f ns2/zone*.example.bk ns2/zones.conf
