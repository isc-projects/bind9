AC_DEFUN([AX_BIND9_LIB_VERSION],
         [AS_IF([test -z "$SED"],
                [AC_PROG_SED])
          AS_IF([test -z "$SED"],
                [AC_MSG_ERROR([sed not found, but required, set \$SED to sed])])
          ax_bind9_lib$1_current=`$SED -n "s,^LIBINTERFACE = \(.*\),\1,p" "$srcdir/lib/$1/api"`
          ax_bind9_lib$1_revision=`$SED -n "s,^LIBREVISION = \(.*\),\1,p" "$srcdir/lib/$1/api"`
          ax_bind9_lib$1_age=`$SED -n "s,^LIBAGE = \(.*\),\1,p" "$srcdir/lib/$1/api"`
          AC_SUBST([lib$1_VERSION_INFO],["-version-info $ax_bind9_lib$1_current:$ax_bind9_lib$1_revision:$ax_bind9_lib$1_age]")
         ])
