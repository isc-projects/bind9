# Hey Emacs, this is -*- makefile-automake -*- file!

NS_INCLUDES = \
	-I$(top_srcdir)/lib/ns/include

lib_LTLIBRARIES += libns.la

libns_ladir = $(include_dir)/ns

libns_la_HEADERS = \
	%reldir%/include/ns/client.h	\
	%reldir%/include/ns/interfacemgr.h	\
	%reldir%/include/ns/lib.h	\
	%reldir%/include/ns/listenlist.h	\
	%reldir%/include/ns/log.h	\
	%reldir%/include/ns/notify.h	\
	%reldir%/include/ns/query.h	\
	%reldir%/include/ns/server.h	\
	%reldir%/include/ns/sortlist.h	\
	%reldir%/include/ns/stats.h	\
	%reldir%/include/ns/types.h	\
	%reldir%/include/ns/update.h	\
	%reldir%/include/ns/xfrout.h

libns_la_SOURCES =			\
	$(libns_la_HEADERS)		\
	%reldir%/client.c		\
	%reldir%/interfacemgr.c		\
	%reldir%/lib.c			\
	%reldir%/listenlist.c		\
	%reldir%/log.c			\
	%reldir%/notify.c		\
	%reldir%/query.c		\
	%reldir%/server.c		\
	%reldir%/sortlist.c		\
	%reldir%/stats.c		\
	%reldir%/update.c		\
	%reldir%/xfrout.c

libns_la_CPPFLAGS = \
	$(AM_CPPFLAGS)			\
	$(ISC_INCLUDES)			\
	$(DNS_INCLUDES)			\
	$(NS_INCLUDES)			\
	$(OPENSSL_CFLAGS)		\
	$(OPENSSL_INCLUDES)

libns_la_LDFLAGS = \
	$(OPENSSL_LDFLAGS)		\
	$(OPENSSL_LIBS)

libns_la_LIBADD =			\
	libisc.la			\
	libdns.la
