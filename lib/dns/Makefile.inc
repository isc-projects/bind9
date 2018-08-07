# Hey Emacs, this is -*- makefile-automake -*- file!

DNS_INCLUDES = \
	-I$(top_srcdir)/lib/dns/include

lib_LTLIBRARIES += libdns.la

BUILT_SOURCES += \
	%reldir%/include/dns/enumclass.h	\
	%reldir%/include/dns/enumtype.h		\
	%reldir%/include/dns/rdatastruct.h	\
	%reldir%/code.h

CLEANFILES += \
	%reldir%/include/dns/enumclass.h	\
	%reldir%/include/dns/enumtype.h		\
	%reldir%/include/dns/rdatastruct.h	\
	%reldir%/code.h

noinst_PROGRAMS = gen

gen_SOURCES = %reldir%/gen.c %reldir%/gen-unix.h

gen_CPPFLAGS = $(AM_CPPFLAGS) $(ISC_INCLUDES)
gen_LIBS = libisc.la

%reldir%/include/dns/enumtype.h: gen
	${builddir}/gen -s %reldir% -t > $@

%reldir%/include/dns/enumclass.h: gen
	${builddir}/gen -s %reldir% -c > $@

%reldir%/include/dns/rdatastruct.h: gen
%reldir%/include/dns/rdatastruct.h: %reldir%/rdata/rdatastructpre.h
%reldir%/include/dns/rdatastruct.h: %reldir%/rdata/rdatastructsuf.h
	${builddir}/gen -s %reldir% -i \
		-P %reldir%/rdata/rdatastructpre.h \
		-S %reldir%/rdata/rdatastructsuf.h > $@

%reldir%/code.h: gen
	${builddir}/gen -s %reldir% > $@

libdns_ladir = $(includedir)/dns
libdns_la_HEADERS =				\
	%reldir%/include/dns/acl.h		\
	%reldir%/include/dns/adb.h		\
	%reldir%/include/dns/badcache.h		\
	%reldir%/include/dns/bit.h		\
	%reldir%/include/dns/byaddr.h		\
	%reldir%/include/dns/cache.h		\
	%reldir%/include/dns/callbacks.h	\
	%reldir%/include/dns/catz.h		\
	%reldir%/include/dns/cert.h		\
	%reldir%/include/dns/client.h		\
	%reldir%/include/dns/clientinfo.h	\
	%reldir%/include/dns/compress.h		\
	%reldir%/include/dns/db.h		\
	%reldir%/include/dns/dbiterator.h	\
	%reldir%/include/dns/dbtable.h		\
	%reldir%/include/dns/diff.h		\
	%reldir%/include/dns/dispatch.h		\
	%reldir%/include/dns/dlz.h		\
	%reldir%/include/dns/dlz_dlopen.h	\
	%reldir%/include/dns/dns64.h		\
	%reldir%/include/dns/dnsrps.h		\
	%reldir%/include/dns/dnssec.h		\
	%reldir%/include/dns/ds.h		\
	%reldir%/include/dns/dsdigest.h		\
	%reldir%/include/dns/dnstap.h		\
	%reldir%/include/dns/dyndb.h		\
	%reldir%/include/dns/ecs.h		\
	%reldir%/include/dns/edns.h		\
	%reldir%/include/dns/ecdb.h		\
	%reldir%/include/dns/events.h		\
	%reldir%/include/dns/fixedname.h	\
	%reldir%/include/dns/forward.h		\
	%reldir%/include/dns/geoip.h		\
	%reldir%/include/dns/ipkeylist.h	\
	%reldir%/include/dns/iptable.h		\
	%reldir%/include/dns/journal.h		\
	%reldir%/include/dns/keydata.h		\
	%reldir%/include/dns/keyflags.h		\
	%reldir%/include/dns/keytable.h		\
	%reldir%/include/dns/keyvalues.h	\
	%reldir%/include/dns/lib.h		\
	%reldir%/include/dns/librpz.h		\
	%reldir%/include/dns/lookup.h		\
	%reldir%/include/dns/log.h		\
	%reldir%/include/dns/master.h		\
	%reldir%/include/dns/masterdump.h	\
	%reldir%/include/dns/message.h		\
	%reldir%/include/dns/name.h		\
	%reldir%/include/dns/ncache.h		\
	%reldir%/include/dns/nsec.h		\
	%reldir%/include/dns/nsec3.h		\
	%reldir%/include/dns/nta.h		\
	%reldir%/include/dns/opcode.h		\
	%reldir%/include/dns/order.h		\
	%reldir%/include/dns/peer.h		\
	%reldir%/include/dns/portlist.h		\
	%reldir%/include/dns/private.h		\
	%reldir%/include/dns/rbt.h		\
	%reldir%/include/dns/rcode.h		\
	%reldir%/include/dns/rdata.h		\
	%reldir%/include/dns/rdataclass.h	\
	%reldir%/include/dns/rdatalist.h	\
	%reldir%/include/dns/rdataset.h		\
	%reldir%/include/dns/rdatasetiter.h	\
	%reldir%/include/dns/rdataslab.h	\
	%reldir%/include/dns/rdatatype.h	\
	%reldir%/include/dns/request.h		\
	%reldir%/include/dns/resolver.h		\
	%reldir%/include/dns/result.h		\
	%reldir%/include/dns/rootns.h		\
	%reldir%/include/dns/rpz.h		\
	%reldir%/include/dns/rriterator.h	\
	%reldir%/include/dns/rrl.h		\
	%reldir%/include/dns/sdb.h		\
	%reldir%/include/dns/sdlz.h		\
	%reldir%/include/dns/secalg.h		\
	%reldir%/include/dns/secproto.h		\
	%reldir%/include/dns/soa.h		\
	%reldir%/include/dns/ssu.h		\
	%reldir%/include/dns/stats.h		\
	%reldir%/include/dns/tcpmsg.h		\
	%reldir%/include/dns/time.h		\
	%reldir%/include/dns/timer.h		\
	%reldir%/include/dns/tkey.h		\
	%reldir%/include/dns/tsec.h		\
	%reldir%/include/dns/tsig.h		\
	%reldir%/include/dns/ttl.h		\
	%reldir%/include/dns/types.h		\
	%reldir%/include/dns/update.h		\
	%reldir%/include/dns/validator.h	\
	%reldir%/include/dns/view.h		\
	%reldir%/include/dns/xfrin.h		\
	%reldir%/include/dns/zone.h		\
	%reldir%/include/dns/zonekey.h		\
	%reldir%/include/dns/zoneverify.h	\
	%reldir%/include/dns/zt.h		\
	%reldir%/include/dst/dst.h		\
	%reldir%/include/dst/gssapi.h		\
	%reldir%/include/dst/lib.h		\
	%reldir%/include/dst/result.h

libdns_la_SOURCES = \
	$(libdns_la_HEADERS)	\
	%reldir%/acl.c		\
	%reldir%/adb.c		\
	%reldir%/badcache.	\
	%reldir%/byaddr.c	\
	%reldir%/cache.c	\
	%reldir%/callbacks.c	\
	%reldir%/clientinfo.c	\
	%reldir%/compress.c	\
	%reldir%/db.c		\
	%reldir%/dbiterator.c	\
	%reldir%/dbtable.c	\
	%reldir%/diff.c		\
	%reldir%/dispatch.c	\
	%reldir%/dlz.c		\
	%reldir%/dns64.c	\
	%reldir%/dnsrps.c	\
	%reldir%/dnssec.c	\
	%reldir%/ds.c		\
	%reldir%/dyndb.c	\
	%reldir%/ecs.c		\
	%reldir%/fixedname.c	\
	%reldir%/forward.c	\
	%reldir%/ipkeylist.c	\
	%reldir%/iptable.c	\
	%reldir%/journal.c	\
	%reldir%/keydata.c	\
	%reldir%/keytable.c	\
	%reldir%/lib.c		\
	%reldir%/log.c		\
	%reldir%/lookup.c	\
	%reldir%/master.c	\
	%reldir%/masterdump.c	\
	%reldir%/message.c	\
	%reldir%/name.c		\
	%reldir%/ncache.c	\
	%reldir%/nsec.c		\
	%reldir%/nsec3.c	\
	%reldir%/nta.c		\
	%reldir%/order.c	\
	%reldir%/peer.c		\
	%reldir%/portlist.c	\
	%reldir%/rbt.c		\
	%reldir%/rbtdb.c	\
	%reldir%/rcode.c	\
	%reldir%/rdata.c	\
	%reldir%/rdatalist.c	\
	%reldir%/rdataset.c	\
	%reldir%/rdatasetiter.c	\
	%reldir%/rdataslab.c	\
	%reldir%/request.c	\
	%reldir%/resolver.c	\
	%reldir%/result.c	\
	%reldir%/rootns.c	\
	%reldir%/rpz.c		\
	%reldir%/rrl.c		\
	%reldir%/rriterator.c	\
	%reldir%/sdb.c		\
	%reldir%/sdlz.c		\
	%reldir%/soa.c		\
	%reldir%/ssu.c		\
	%reldir%/ssu_external.c	\
	%reldir%/stats.c	\
	%reldir%/tcpmsg.c	\
	%reldir%/time.c		\
	%reldir%/timer.c	\
	%reldir%/tkey.c		\
	%reldir%/tsec.c		\
	%reldir%/tsig.c		\
	%reldir%/ttl.c		\
	%reldir%/update.c	\
	%reldir%/validator.c	\
	%reldir%/view.c		\
	%reldir%/xfrin.c	\
	%reldir%/zone.c		\
	%reldir%/zoneverify.c	\
	%reldir%/zonekey.c	\
	%reldir%/zt.c		\
	%reldir%/client.c	\
	%reldir%/ecdb.c

if HAVE_GEOIP
libdns_la_SOURCES += \
	%reldir%/geoip.c
endif

if HAVE_DNSTAP
BUILT_SOURCES += \
	%reldir%/dnstap.pb-c.h	\
	%reldir%/dnstap.c	\
	%reldir%/dnstap.pb-c.c

libdns_la_SOURCES +=		\
	%reldir%/dnstap.c	\
	%reldir%/dnstap.pb-c.h	\
	%reldir%/dnstap.pb-c.c

CLEANFILES +=			\
	%reldir%/dnstap.c	\
	%reldir%/dnstap.pb-c.h	\
	%reldir%/dnstap.pb-c.c

%reldir%/dnstap.c %reldir%/dnstap.pb-c.h %reldir%/dnstap.pb-c.c: %reldir%/dnstap.proto
	$(PROTOC_C) --c_out=%reldir% $<

endif

libdns_la_CPPFLAGS =		\
	$(ISC_INCLUDES)		\
	$(DNS_INCLUDES)		\
	$(USE_ISC_SPNEGO)	\
	$(OPENSSL_CFLAGS)	\
	$(OPENSSL_INCLUDES)	\
	$(DST_GSSAPI_INC)	\
	$(USE_GSSAPI)		\
	-DUSE_MD5

libdns_la_LDFLAGS =		\
	$(OPENSSL_LDFLAGS)	\
	$(OPENSSL_LIBS)

libdns_la_LIBADD =		\
	libisc.la
