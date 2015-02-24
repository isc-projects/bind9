#!/bin/sh
#
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
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

rm -f */K* */*.signed */trusted.conf */*.jnl */*.bk
rm -f dsset-. ns1/dsset-.
rm -f ns*/named.lock
rm -f */managed-keys.bind* */named.secroots
rm -f */managed.conf ns1/managed.key ns1/managed.key.id
rm -f */named.memstats */named.run
rm -f dig.out* delv.out* rndc.out* signer.out*
rm -f ns1/named.secroots ns1/root.db.signed* ns1/root.db.tmp
rm -f ns1/named.conf
