#!/bin/sh
#
# Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
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

status=0

#
# Check for missing #include <isc/print.h> or "print_p.h"
#
list=`git grep -l snprintf lib bin |
      grep '\.c$' |
      grep -vE -e '(lib/bind|lib/dns/rdata|lib/dns/gen.c)' \
	       -e '(lib/isc/win32/time.c|dlzexternal/driver.c)' |
      xargs grep -EL "(isc/print.h|print_p.h)" 2> /dev/null`
[ -n "$list" ] && {
    status=1
    echo 'Missing #include <isc/print.h> or #include "print_p.h":'
    echo "$list"
}

#
# Check for missing #include <isc/string.h>"
#
list=`git grep -lw strsep lib bin |
      grep '\.c$' |
      grep -vE -e '(lib/bind|lib/dns/rdata|lib/dns/gen.c)' \
	       -e '(lib/isc/win32/time.c)' |
      xargs grep -L "<isc/string.h>"`
[ -n "$list" ] && {
    status=1
    echo 'Missing #include <isc/string.h>:'
    echo "$list"
}

#
# Check for missing #include <inttypes.h>"
#
list=`git grep -l uintptr_t lib bin |
      grep '\.c$' |
      grep -vE -e '(lib/bind|lib/dns/rdata|lib/dns/gen.c)' \
	       -e '(lib/isc/win32/time.c)' |
      xargs grep -L "<inttypes.h>"`
[ -n "$list" ] && {
    status=1
    echo 'Missing #include <inttypes.h>:'
    echo "$list"
}

#
# Check for missing #include <config.h>
#
list=`git ls-files -c bin lib | grep '\.c$' |
      xargs grep -L '#include ["<]config.h[">]' |
      grep -vE -e '(/win32/|bin/pkcs11/|lib/dns/rdata|lib/bind/)' \
	       -e '(ifiter_|lib/dns/gen.c|lib/dns/spnego_asn1.c)' \
	       -e '(lib/dns/rbtdb64.c|lib/isc/entropy.c|lib/isc/fsaccess.c)' \
	       -e '(bin/tests/virtual-time/vtwrapper.c|symtbl.c|version.c)'`
[ -n "$list" ] && {
    status=1
    echo 'Missing #include "config.h":'
    echo "$list"
}

list=`git ls-files -c lib bin | grep '\.vcxproj\.in$' |
      xargs grep -L '<ProjectGuid>' |
      awk '{a[$2]++;} END { for (g in a) if (a[g] != 1) print g;}'`
[ -n "$list" ] && {
    status=1
    echo 'duplicate <ProjectGuid>'"'"'s:'
    echo "$list"
}

for lib in `git ls-files -c lib |
	    sed -n 's;^lib/\([^/]*\)/win32/.*\.def.*$;\1;p' |
	    sort -u`
do
    def=`git ls-files -c lib |
	 grep lib/${lib}/win32/lib${lib}.def |
	 sort |
	 tail -n 1`
    test -z "$def" && continue;
    test -f "$def" || continue;
    dirs=
    test -d lib/$lib/include && dirs="$dirs lib/$lib/include"
    test -d lib/$lib/win32/include && dirs="$dirs lib/$lib/win32/include"
    test -z "$dirs" && continue;
    pat=$lib
    test $lib = dns && pat='\(dns\|dst\)'
    pat="^${pat}_[a-z0-9_]*("
    list=`git ls-files -c $dirs | grep '\.h$' |
	  xargs grep "$pat" |
	  sed -e 's/.*://' -e 's/(.*//' |
	  while read p
	  do
	      case $p in
	      isc__app_register) continue;;                     # internal
	      isc__mem_register) continue;;                     # internal
	      isc__task_register) continue;;                    # internal
	      isc__taskmgr_dispatch) continue;;                 # internal
	      isc__timer_register) continue;;                   # internal
	      isc_ntsecurity_getaccountgroups) continue;;       # internal
	      isc__taskmgr_dispatch) continue;;			# no threads
	      isc__taskmgr_ready) continue;;			# no threads
	      isc_socketmgr_getmaxsockets) p=isc__socketmgr_getmaxsockets;;
	      esac
	      grep -q "^${p}"'$' $def && continue
	      test $lib = isc -a -f lib/isc/win32/libisc.def.exclude &&
		  grep -q "^${p}"'$' lib/isc/win32/libisc.def.exclude &&
		  continue
	      if test -d lib/$lib/win32
	      then
		  grep -q "^$p(" lib/$lib/*.c lib/$lib/win32/*.c && echo "$p"
	      else
		  grep -q "^$p(" lib/$lib/*.c && echo "$p"
	      fi
	  done`
    [ -n "$list" ] && {
	status=1
	echo "Missing from ${def}:"
	echo "$list"
    }
done

exit $status
