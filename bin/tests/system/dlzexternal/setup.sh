#!/bin/sh

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

../../../tools/genrandom 400 random.data
$DDNSCONFGEN -q -r random.data -z example.nil > ns1/ddns.key
