#!/bin/sh

rm -f */K* */*.keyset */*.signedkey */*.signed */trusted.conf
rm -f ns1/root.db ns2/example.db ns3/secure.example.db
rm -f ns3/unsecure.example.db ns3/bogus.example.db
rm -f dig.out.*
