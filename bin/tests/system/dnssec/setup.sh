#!/bin/sh

cd ns1 && sh sign.sh

echo "a.bogus.example.	A	10.0.0.22" >>../ns3/bogus.example.db.signed
