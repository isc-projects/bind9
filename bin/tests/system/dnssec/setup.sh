#!/bin/sh

cd ns2 && sh sign.sh

if [ $# -gt 0 ]
then
   case $1 in
	--badsig)
	   echo "injecting bogus data to force signature checking to fail..." >&2
	   echo "a.secure.example.	A	10.0.0.22" >>../ns3/secure.example.db.signed
	;;
	
	*)
	    echo "unknown option $1" >&2; exit 1
	;;
    esac
fi
