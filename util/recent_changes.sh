#!/bin/sh
#
# Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
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

# Find the list of files that have been touched in the Git repository
# during the current calendar year.  This is done by walking backwards
# through the output of "git whatchanged" until a year other than the
# current one is seen.  Used by merge_copyrights.

thisyear=`date +%Y`
when="`expr $thisyear - 1`-12-31"
git whatchanged --since="$when" --pretty="" | awk '
    BEGIN { change=0 }
    NF == 0 { next; }
    $(NF-1) ~ /[AM]/ { print "./" $NF; change=1 }
    END { if (change) print "./COPYRIGHT" } ' | sort | uniq
