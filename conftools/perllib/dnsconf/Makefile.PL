use ExtUtils::MakeMaker;

$ENV{CC} = "gcc";

WriteMakefile('NAME' => 'DNSConf',
	      'OPTIMIZE' => '-g',
	      'PERLMAINCC' => 'gcc',
	      'LIBS' => [ '-L../../isc -L../../dns -ldns -lisc -lc_r' ],
	      'INC' => '-I../../isc/include -I../../isc/unix/include -I../../dns/include',
	      'dynamic_lib' => { OTHERLDFLAGS => '-pthread' },
	      'OBJECT' => 'DNSConf_wrap.o');
