#!/bin/sh

TOP=${SYSTEMTESTTOP:=.}/../../../..

# enable the dlzexternal test only if it builds and dlz-dlopen was enabled
$TOP/bin/named/named -V | grep with.dlz.dlopen | grep -v with.dlz.dlopen=no > /dev/null || {
    echo "I:not built with --with-dlz-dlopen=yes - skipping dlzexternal test"
    exit 1
}

cd ../../../../contrib/dlz/example && make all > /dev/null || {
    echo "I:build of dlz_example.so failed - skipping dlzexternal test"
    exit 1
}
exit 0


