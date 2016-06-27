# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: Makefile.PL,v 1.9 2007/06/19 23:47:07 tbox Exp $

use ExtUtils::MakeMaker;

$ENV{CC} = "gcc";

WriteMakefile('NAME' => 'DNSConf',
	      'OPTIMIZE' => '-g',
	      'PERLMAINCC' => 'gcc',
	      'LIBS' => [ '-L../../isc -L../../dns -ldns -lisc -lc_r' ],
	      'INC' => '-I../../isc/include -I../../isc/unix/include -I../../dns/include',
	      'dynamic_lib' => { OTHERLDFLAGS => '-pthread' },
	      'OBJECT' => 'DNSConf_wrap.o');
