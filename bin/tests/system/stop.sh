#!/bin/sh
#
# Stop name servers.
#

cd $1

for d in ns*
do
     pidfile="$d/named.pid"
     test ! -f $pidfile || kill -INT `cat $pidfile`
done
