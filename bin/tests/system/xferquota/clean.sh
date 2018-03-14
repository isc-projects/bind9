#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) Internet Software Consortium.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

#
# Clean up after zone transfer quota tests.
#

rm -f ns1/zone*.example.db ns1/zones.conf
rm -f ns2/zone*.example.bk ns2/zones.conf
rm -f dig.out.* ns2/changing.bk
rm -f ns1/changing.db
rm -f */named.memstats
rm -f */named.conf
rm -f */named.run
