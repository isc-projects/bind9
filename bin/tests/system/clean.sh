#!/bin/sh
#
# Copyright (C) 2000  Internet Software Consortium.
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
# CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
# PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.

# $Id: clean.sh,v 1.7 2000/06/22 21:51:23 tale Exp $

#
# Clean up after system tests.
#

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

find . -type f \( \
    -name 'K*' -o -name '*~' -o -name '*.core' -o -name '*.log' \
    -o -name '*.pid' -o -name '*.keyset' \
\) -print | xargs rm -f

for d in $SUBDIRS
do
   test ! -f $d/clean.sh || ( cd $d && sh clean.sh )
done
