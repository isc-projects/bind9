include $(top_srcdir)/Makefile.top

lib_LTLIBRARIES = libisc.la

libisc_ladir = $(includedir)/isc
libisc_la_HEADERS =			\
	include/isc/aes.h		\
	include/isc/app.h		\
	include/isc/assertions.h	\
	include/isc/astack.h		\
	include/isc/atomic.h		\
	include/isc/attributes.h	\
	include/isc/backtrace.h		\
	include/isc/base32.h		\
	include/isc/base64.h		\
	include/isc/bind9.h		\
	include/isc/buffer.h		\
	include/isc/bufferlist.h	\
	include/isc/commandline.h	\
	include/isc/counter.h		\
	include/isc/crc64.h		\
	include/isc/deprecated.h	\
	include/isc/endian.h		\
	include/isc/errno.h		\
	include/isc/error.h		\
	include/isc/event.h		\
	include/isc/eventclass.h	\
	include/isc/file.h		\
	include/isc/formatcheck.h	\
	include/isc/fsaccess.h		\
	include/isc/fuzz.h		\
	include/isc/glob.h		\
	include/isc/hash.h		\
	include/isc/heap.h		\
	include/isc/hex.h		\
	include/isc/hmac.h		\
	include/isc/hp.h		\
	include/isc/ht.h		\
	include/isc/httpd.h		\
	include/isc/interfaceiter.h	\
	include/isc/iterated_hash.h	\
	include/isc/lang.h		\
	include/isc/lex.h		\
	include/isc/lib.h		\
	include/isc/likely.h		\
	include/isc/list.h		\
	include/isc/log.h		\
	include/isc/magic.h		\
	include/isc/md.h		\
	include/isc/mem.h		\
	include/isc/meminfo.h		\
	include/isc/mutexatomic.h	\
	include/isc/mutexblock.h	\
	include/isc/netaddr.h		\
	include/isc/netmgr.h		\
	include/isc/netscope.h		\
	include/isc/nonce.h		\
	include/isc/os.h		\
	include/isc/parseint.h		\
	include/isc/pool.h		\
	include/isc/portset.h		\
	include/isc/platform.h		\
	include/isc/print.h		\
	include/isc/queue.h		\
	include/isc/quota.h		\
	include/isc/radix.h		\
	include/isc/random.h		\
	include/isc/ratelimiter.h	\
	include/isc/refcount.h		\
	include/isc/regex.h		\
	include/isc/region.h		\
	include/isc/resource.h		\
	include/isc/result.h		\
	include/isc/resultclass.h	\
	include/isc/rwlock.h		\
	include/isc/safe.h		\
	include/isc/serial.h		\
	include/isc/siphash.h		\
	include/isc/sockaddr.h		\
	include/isc/socket.h		\
	include/isc/stats.h		\
	include/isc/stdio.h		\
	include/isc/strerr.h		\
	include/isc/string.h		\
	include/isc/symtab.h		\
	include/isc/task.h		\
	include/isc/taskpool.h		\
	include/isc/timer.h		\
	include/isc/tm.h		\
	include/isc/types.h		\
	include/isc/utf8.h		\
	include/isc/util.h		\
	pthreads/include/isc/condition.h\
	pthreads/include/isc/mutex.h	\
	pthreads/include/isc/once.h	\
	pthreads/include/isc/thread.h	\
	unix/errno2result.h		\
	unix/include/isc/align.h	\
	unix/include/isc/dir.h		\
	unix/include/isc/netdb.h	\
	unix/include/isc/net.h		\
	unix/include/isc/offset.h	\
	unix/include/isc/stat.h		\
	unix/include/isc/stdatomic.h	\
	unix/include/isc/stdtime.h	\
	unix/include/isc/syslog.h	\
	unix/include/isc/time.h

pk11dir = $(includedir)/pk11
pk11_HEADERS =				\
	include/pk11/constants.h	\
	include/pk11/internal.h		\
	include/pk11/pk11.h		\
	include/pk11/result.h		\
	include/pk11/site.h

pkcs11dir = $(includedir)/pkcs11
pkcs11_HEADERS =		\
	include/pkcs11/pkcs11.h

libisc_la_SOURCES =		\
	$(libisc_la_HEADERS)	\
	$(pk11_HEADERS)		\
	$(pkcs11_HEADERS)	\
	netmgr/netmgr-int.h	\
	netmgr/netmgr.c		\
	netmgr/tcp.c		\
	netmgr/tcpdns.c		\
	netmgr/udp.c		\
	netmgr/uv-compat.c	\
	netmgr/uv-compat.h	\
	netmgr/uverr2result.c	\
	unix/pk11_api.c		\
	unix/dir.c		\
	unix/errno.c		\
	unix/errno2result.c	\
	unix/file.c		\
	unix/fsaccess.c		\
	unix/interfaceiter.c	\
	unix/meminfo.c		\
	unix/net.c		\
	unix/os.c		\
	unix/resource.c		\
	unix/socket.c		\
	unix/stdio.c		\
	unix/stdtime.c		\
	unix/syslog.c		\
	unix/time.c		\
	pk11.c			\
	pk11_result.c		\
	aes.c			\
	app.c			\
	assertions.c		\
	astack.c		\
	backtrace.c		\
	base32.c		\
	base64.c		\
	bind9.c			\
	buffer.c		\
	bufferlist.c		\
	commandline.c		\
	counter.c		\
	crc64.c			\
	entropy.c		\
	error.c			\
	event.c			\
	fsaccess_common.c	\
	glob.c			\
	hash.c			\
	hp.c			\
	ht.c			\
	heap.c			\
	hex.c			\
	hmac.c			\
	httpd.c			\
	iterated_hash.c		\
	lex.c			\
	lib.c			\
	log.c			\
	md.c			\
	mem.c			\
	mutexblock.c		\
	netaddr.c		\
	netscope.c		\
	nonce.c			\
	openssl_shim.c		\
	queue.c			\
	openssl_shim.h		\
	pool.c			\
	parseint.c		\
	portset.c		\
	quota.c			\
	radix.c			\
	random.c		\
	ratelimiter.c		\
	region.c		\
	regex.c			\
	result.c		\
	rwlock.c		\
	safe.c			\
	serial.c		\
	siphash.c		\
	sockaddr.c		\
	stats.c			\
	string.c		\
	symtab.c		\
	task.c			\
	taskpool.c		\
	timer.c			\
	tm.c			\
	utf8.c			\
	pthreads/condition.c	\
	pthreads/mutex.c	\
	pthreads/thread.c	\
	entropy_private.h	\
	fsaccess_common_p.h	\
	mem_p.h			\
	task_p.h		\
	timer_p.h

libisc_la_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBISC_CFLAGS)	\
	$(LIBUV_CFLAGS)		\
	$(OPENSSL_CFLAGS)	\
	$(ZLIB_CFLAGS)

libisc_la_LDFLAGS =		\
	$(libisc_VERSION_INFO)

libisc_la_LIBADD =		\
	$(LIBLTDL_LIBS)		\
	$(LIBUV_LIBS)		\
	$(OPENSSL_LIBS)		\
	$(ZLIB_LIBS)

if HAVE_JSON_C
libisc_la_CPPFLAGS +=		\
	$(JSON_C_CFLAGS)

libisc_la_LIBADD +=		\
	$(JSON_C_LIBS)
endif HAVE_JSON_C

if HAVE_LIBXML2
libisc_la_CPPFLAGS +=		\
	$(LIBXML2_CFLAGS)

libisc_la_LIBADD +=		\
	$(LIBXML2_LIBS)
endif HAVE_LIBXML2

if HAVE_CMOCKA
SUBDIRS = tests
endif

EXTRA_DIST = api
