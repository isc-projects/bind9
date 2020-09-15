#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

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
# Check for missing #include <isc/strerr.h>
#
list=`git grep -wl strerror_r lib bin |
      grep '\.c$' |
      grep -vE -e '(lib/bind|lib/dns/rdata|lib/dns/gen.c)' \
	       -e lib/isc/string.c \
	       -e '(lib/isc/win32/time.c|dlzexternal/driver.c)' |
      xargs grep -EL "(isc/strerr.h)" 2> /dev/null`
[ -n "$list" ] && {
    status=1
    echo 'Missing #include <isc/strerr.h>:'
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
    test $lib = isccfg && pat='cfg'
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
