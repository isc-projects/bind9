#!/bin/sh

PATH=${PATH}:/home/each/isc/bind97x/unit/atf/bin
export PATH

atf-run | atf-report
