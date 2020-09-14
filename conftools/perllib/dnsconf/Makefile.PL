# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

use ExtUtils::MakeMaker;

$ENV{CC} = "gcc";

WriteMakefile('NAME' => 'DNSConf',
	      'OPTIMIZE' => '-g',
	      'PERLMAINCC' => 'gcc',
	      'LIBS' => [ '-L../../isc -L../../dns -ldns -lisc -lc_r' ],
	      'INC' => '-I../../isc/include -I../../isc/unix/include -I../../dns/include',
	      'dynamic_lib' => { OTHERLDFLAGS => '-pthread' },
	      'OBJECT' => 'DNSConf_wrap.o');
