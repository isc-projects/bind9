#!/bin/sh

RANDFILE=../random.data

keyname=`$KEYGEN -a DH -b 768 -n host -r $RANDFILE server`
keyid=`echo $keyname | perl -p -e 's/^.*\+//;'`
rm -f named.conf
perl -p -e "s/KEYID/$keyid/;" < named.conf.in > named.conf
