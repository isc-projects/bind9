#!/bin/sh
#
# Copyright (C) 2000  Internet Software Consortium.
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: tests.sh,v 1.3 2000/07/27 09:40:40 tale Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#
# Perform tests
#

status=0

# If the server has the "INSIST(!external)" bug, this query will kill it.
$DIG +tcp example. dig www.example.com. a @10.53.0.1 -p 5300 >/dev/null || status=1

# Query once more to see if the server is still alive.
$DIG +tcp example. dig www.example.com. a @10.53.0.1 -p 5300 >/dev/null || status=1

echo "I:exit status: $status"
exit $status
