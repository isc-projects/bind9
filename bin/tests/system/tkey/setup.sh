#!/bin/sh

RANDFILE=random.data

../../genrandom 100 $RANDFILE

cd ns1 && sh setup.sh
