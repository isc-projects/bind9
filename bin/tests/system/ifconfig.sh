#!/bin/sh
#
# Set up interface aliases for bind9 system tests.
#

for ns in 1 2 3 4
do 
   ifconfig lo0 10.53.0.$ns alias
done
