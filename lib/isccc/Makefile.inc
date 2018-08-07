# Hey Emacs, this is -*- makefile-automake -*- file!

ISCCC_INCLUDES = \
	-I$(top_srcdir)/lib/isccc/include/

lib_LTLIBRARIES += libisccc.la

libisccc_ladir = $(includedir)/isccc
libisccc_la_HEADERS = 			\
	%reldir%/include/isccc/alist.h	\
	%reldir%/include/isccc/base64.h	\
	%reldir%/include/isccc/cc.h	\
	%reldir%/include/isccc/ccmsg.h	\
	%reldir%/include/isccc/events.h	\
	%reldir%/include/isccc/lib.h	\
	%reldir%/include/isccc/result.h	\
	%reldir%/include/isccc/sexpr.h	\
	%reldir%/include/isccc/symtab.h	\
	%reldir%/include/isccc/symtype.h\
	%reldir%/include/isccc/types.h	\
	%reldir%/include/isccc/util.h

libisccc_la_SOURCES =			\
	$(libisccc_la_HEADERS)		\
	%reldir%/alist.c		\
	%reldir%/base64.c		\
	%reldir%/cc.c			\
	%reldir%/ccmsg.c		\
	%reldir%/lib.c			\
	%reldir%/result.c		\
	%reldir%/sexpr.c		\
	%reldir%/symtab.c

libisccc_la_CPPFLAGS =			\
	$(AM_CPPFLAGS)			\
	$(ISC_INCLUDES)			\
	$(DNS_INCLUDES)			\
	$(ISCCC_INCLUDES) 		\
	$(OPENSSL_INCLUDES)

libisccc_la_LDFLAGS =			\
	$(OPENSSL_LDFLAGS)		\
	$(OPENSSL_LIBS)

libisccc_la_LIBADD =			\
	libisc.la
