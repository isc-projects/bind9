# SPDX-License-Identifier: FSFAP
#
# SYNOPSIS
#
#   AX_PERL_MODULE(MODULE[, ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
#
# DESCRIPTION
#
#   Checks for Perl module.
#
# LICENSE
#
#   Copyright (c) 2020 Internet Systems Consortium
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AC_DEFUN([AX_PERL_MODULE],[
    AC_MSG_CHECKING([for perl module: $1])
    $PERL "-M$1" -e exit >/dev/null 2>&1
    AS_IF([test $? -eq 0],
          [AC_MSG_RESULT([yes])
           eval AS_TR_CPP(HAVE_PERLMOD_$1)=yes
           $2
          ],
          [AC_MSG_RESULT([no])
           eval AS_TR_CPP(HAVE_PERLMOD_$1)=no
           $3
          ])
    ])
