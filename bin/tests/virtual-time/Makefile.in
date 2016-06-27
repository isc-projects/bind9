# Copyright (C) 2010, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: Makefile.in,v 1.2 2010/06/17 05:38:04 marka Exp $

TARGETS =	libvtwrapper.so
SRCS =		vtwrapper.c
CFLAGS +=	-fPIC
LDFLAGS =
LIBS =

all: libvtwrapper.so

.SUFFIXES: .c .o

.c.o:
	${CC} ${CFLAGS} -c $<

libvtwrapper.so: vtwrapper.o
	${CC} ${CFLAGS} ${LDFLAGS} -nostdlib -export-dynamic -shared -o $@ vtwrapper.o ${LIBS}

clean distclean::
	rm -f ${TARGETS} *.o

SUBDIRS =

test:
	if test -f ./runall.sh; then sh ./runall.sh; fi

testclean clean distclean::
	if test -f ./cleanall.sh; then sh ./cleanall.sh; fi

distclean::
	rm -f conf.sh
