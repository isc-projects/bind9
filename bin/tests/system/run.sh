#!/bin/sh
#
# Run a system test.
#
. ./conf.sh

test $# -gt 0 || { echo "usage: runtest.sh test-directory" >&2; exit 1; }

test=$1
shift

test -d $test || { echo "$0: $test: no such test" >&2; exit 1; }

# Set up any dynamically generated test data
if test -f $test/setup.sh
then
   ( cd $test && sh setup.sh "$@" )
fi

# Start name servers running
sh start.sh $test

# Run the tests
( cd $test ; sh tests.sh )

echo "Result code $?"

# Shutdown
sh stop.sh $test
