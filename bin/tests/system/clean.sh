#!/bin/sh
#
# Clean up after system tests.
#

. ./conf.sh

find . -type f \( \
    -name 'K*' -o -name '*~' -o -name '*.core' -o -name '*.log' \
    -o -name '*.pid' -o -name '*.run' -o -name '*.keyset' \
\) -print | xargs rm

for d in $SUBDIRS
do
   test ! -f $d/clean.sh || ( cd $d && sh clean.sh )
done
