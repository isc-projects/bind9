/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* $Id: log.h,v 1.8 2000/02/03 23:07:50 halley Exp $ */

#ifndef ISC_LOG_H
#define ISC_LOG_H 1

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>

#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

/*
 * Severity levels, patterned after Unix's syslog levels.
 *
 * ISC_LOG_DYNAMIC can only be used for defining channels with
 * isc_log_createchannel(), not to specify a level in isc_log_write().
 */
#define ISC_LOG_DEBUG(level)	(level)
#define ISC_LOG_DYNAMIC	  	  0
#define ISC_LOG_INFO		(-1)
#define ISC_LOG_NOTICE		(-2)
#define ISC_LOG_WARNING 	(-3)
#define ISC_LOG_ERROR		(-4)
#define ISC_LOG_CRITICAL	(-5)

/*
 * Destinations.
 */
#define ISC_LOG_TONULL		1
#define ISC_LOG_TOSYSLOG	2
#define ISC_LOG_TOFILE		3
#define ISC_LOG_TOFILEDESC	4

/*
 * Channel flags.
 */
#define ISC_LOG_PRINTTIME	0x0001
#define ISC_LOG_PRINTLEVEL	0x0002
#define ISC_LOG_PRINTCATEGORY	0x0004
#define ISC_LOG_PRINTMODULE	0x0008
#define ISC_LOG_PRINTALL	0x000F

/*
 * Other options.
 * XXXDCL INFINITE doesn't yet work.  Arguably it isn't needed, but
 *   since I am intend to make large number of versions work efficiently,
 *   INFINITE is going to be trivial to add to that.
 */
#define ISC_LOG_ROLLINFINITE	(-1)
#define ISC_LOG_ROLLNEVER	(-2)

/*
 * A logging context.  Details are internal to the implementation.
 */
typedef struct isc_log isc_log_t;

/*
 * Used to name the categories used by a library.  An array of isc_logcategory
 * structures names each category, and the id value is initialized by calling
 * isc_log_registercategories.
 */
typedef struct isc_logcategory {
	const char *name;
	unsigned int id;
} isc_logcategory_t;

/*
 * Similar to isc_logcategory above, but for all the modules a library defines.
 */
typedef struct isc_logmodule {
	const char *name;
	unsigned int id;
} isc_logmodule_t;

/*
 * The isc_logfile structure is initialized as part of an isc_logdestination
 * before calling isc_log_createchannel().  When defining an ISC_LOG_TOFILE
 * channel the name, versions and maximum_size should be set before calling
 * isc_log_createchannel().  To define an ISC_LOG_TOFILEDESC channel set only
 * the stream before the call.
 */
typedef struct isc_logfile {
	FILE *stream;	/* Initialized to NULL for ISC_LOG_TOFILE. */
	char *name;	/* NULL for ISC_LOG_TOFILEDESC. */
	int versions;	/* >= 0, ISC_LOG_ROLLNEVER, ISC_LOG_ROLLINFINITE. */
	/*
	 * stdio's ftell is standardized to return a long, which may well not
	 * be big enough for the largest file supportable by the operating
	 * system (though it is _probably_ big enough for the largest log
	 * anyone would want).  st_size returned by fstat should be typedef'd
	 * to a size large enough for the largest possible file on a system.
	 */
	/* XXXDCL NT */
	off_t maximum_size;
} isc_logfile_t;

/*
 * Passed to isc_log_createchannel to define the attributes of either
 * a stdio or a syslog log.
 */
typedef union isc_logdestination {
	isc_logfile_t file;
	int facility;		/* XXXDCL NT */
} isc_logdestination_t;

/*
 * The built-in categories of libisc.a.  Currently only one is available,
 * the category named "default".
 *
 * Each library registering categories should provide library_LOGCATEGORY_name
 * definitions with indexes into its isc_logcategory structure corresponding to
 * the order of the names.  This should also be done for modules, but currently
 * libisc.a has no defined modules.
 */
extern isc_logcategory_t isc_categories[];

#define ISC_LOGCATEGORY_DEFAULT	(&isc_categories[0])

isc_result_t
isc_log_create(isc_mem_t *mctx, isc_log_t **lctxp);
/*
 * Establish a new logging context, with default channels.
 *
 * Notes:
 *	Four default channels are established:
 *	    	default_syslog
 *		 - log to syslog's daemon facility LOG_INFO or higher
 *		default_stderr
 *		 - log to stderr LOG_INFO or higher
 *		default_debug
 *		 - log to stderr LOG_DEBUG dynamically
 *		null
 *		 - log nothing
 *
 * Requires:
 *	mctx is a valid memory context.
 *	lctxp is not null and *lctxp is null.
 *
 * Ensures:
 *	*lctxp will point to a valid logging context if all of the necessary
 *	memory was allocated, or NULL otherwise.
 *
 * Returns:
 *	ISC_R_SUCCESS		Success
 *	ISC_R_NOMEMORY		Resource limit: Out of memory
 *	ISC_R_UNEXPECTED	The mutex lock could not be initialized.
 */

void
isc_log_destroy(isc_log_t **lctxp);
/*
 * Deallocate the memory associated with a logging context.
 *
 * Requires:
 *	*lctx is a valid logging context.
 *
 * Ensures:
 *	All of the memory associated with the logging context is returned
 *	to the free memory pool.
 *
 *	Any open files are closed.
 *
 *	The logging context is marked as invalid.
 */


isc_result_t
isc_log_registercategories(isc_log_t *lctx, isc_logcategory_t categories[]);
/*
 * Identify logging categories a library will use.
 *
 * Notes:
 *	The end of the categories array is identified by a NULL name.
 *
 *	Because the name is used by ISC_LOG_PRINTCATEGORY, it should not
 *	be altered or destroyed after isc_log_registercategories().
 *
 *	The value of the id integer in each structure is overwritten
 *	by this function, and so id need not be initalized to any particular
 *	value prior to the function call.
 *
 * Requires:
 *	lctx is a valid logging context.
 *	categories != NULL.
 *
 * Ensures:
 *	ISC_R_SUCCESS
 *		There are references to each category in the logging context,
 *		so they can be used with isc_log_usechannel() and
 *		isc_log_write().
 *
 *	ISC_R_NOMEMORY
 *		No additional memory is in use by the logging context.
 *
 *		The count of categories in the logging context is not updated,
 *		so a subsequent call when more memory is available will Do
 *		The Right Thing.
 *
 *		Does _not_ ensure that any id in categories[] is unchanged.
 *
 * Returns:
 *	ISC_R_SUCCESS	Success
 *	ISC_R_NOMEMORY	Resource limit: Out of memory
 */

void
isc_log_registermodules(isc_log_t *lctx, isc_logmodule_t modules[]);
/*
 * Identify logging categories a library will use.
 *
 * Notes:
 *	The end of the modules array is identified by a NULL name.
 *
 *	Because the name is used by ISC_LOG_PRINTMODULE, it should not
 *	be altered or destroyed after isc_log_registermodules().
 *
 *	The value of the id integer in each structure is overwritten
 *	by this function, and so id need not be initalized to any particular
 *	value prior to the function call.
 *
 * Requires:
 *	lctx is a valid logging context.
 *	modules != NULL.
 *
 * Ensures:
 *	Each module has a reference in the logging context, so they can be
 *	used with isc_log_usechannel() and isc_log_write().
 */

isc_result_t
isc_log_createchannel(isc_log_t *lctx, const char *name, unsigned int type,
		      int level, isc_logdestination_t *destination,
		      unsigned int flags);
/*
 * Specify the parameters of a logging channel.
 *
 * Notes:
 *	The name argument is copied to memory in the logging context, so
 *	it can be altered or destroyed after isc_log_createchannel().
 *
 *	Defining a very large number of channels will have a performance
 *	impact on isc_log_usechannel(), since the names are searched
 *	linearly until a match is made.  This same issue does not affect
 *	isc_log_write, however.
 *
 *	Channel names can be redefined; this is primarily useful for programs
 *	that want their own definition of default_syslog, default_debug
 *	and default_stderr.
 *
 *	Any channel that is redefined will not affect logging that was
 *	already directed to its original definition, _except_ for the
 *	default_stderr channel.  This case is handled specially so that
 *	the default logging category can be changed by redefining
 *	default_stderr.  (XXXDCL Though now that I think of it, the default
 *	logging category can be changed with only one additional function
 *	call by defining a new channel and then calling isc_log_usechannel()
 *	for ISC_LOGCATEGORY_DEFAULT.)
 *
 *	Specifying ISC_LOG_PRINTTIME for syslog is allowed, but probably
 *	not what you wanted to do.
 *
 * Requires:
 *	lctx is a valid logging context.
 *
 *	name is not NULL.
 *
 *	type is ISC_LOG_TOSYSLOG, ISC_LOG_TOFILE, ISC_LOG_TOFILEDESC or
 *		ISC_LOG_TONULL.
 *
 *	destination is not NULL unless type is ISC_LOG_TONULL.
 *
 *	level is >= ISC_LOG_CRITICAL (the most negative logging level).
 *
 *	flags does not include any bits aside from the ISC_LOG_PRINT* bits.
 *
 * Ensures:
 *	ISC_R_SUCCESS
 *		A channel with the given name is usable with
 *		isc_log_usechannel().
 *
 *	ISC_R_NOMEMORY or ISC_R_UNEXPECTED
 *		No additional memory is being used by the logging context.
 *
 *		Any channel that previously existed with the given name
 *		is not redefined.
 *
 * Returns:
 *	ISC_R_SUCCESS		Success
 *	ISC_R_NOMEMORY		Resource limit: Out of memory
 *	ISC_R_UNEXPECTED	type was out of ranged and REQUIRE()
 *					was disabled.
 */

isc_result_t
isc_log_usechannel(isc_log_t *lctx, const char *name,
		   isc_logcategory_t *category, isc_logmodule_t *module);
/*
 * Associate a named logging channel with a category and module that
 * will use it.
 *
 * Notes:
 *	The name is searched for linearly in the set of known channel names
 *	until a match is found.  (Note the performance impact of a very large
 *	number of named channels.)  When multiple channels of the same
 *	name are defined, the most recent definition is found.
 *
 *	Specifing a very large number of channels for a category will have
 *	a moderate impact on performance in isc_log_write(), as each
 *	call looks up the category for the start of a linked list, which
 *	it follows all the way to the end to find matching modules.  The
 *	test for matching modules is  integral, though.
 *
 *	If category is NULL, then the channel is associated with the indicated
 *	module for all known categories (including the "default" category).
 *
 *	If module is NULL, then the channel is associated with every module
 *	that uses that category.
 *
 *	Passing both category and module as NULL would make every log message
 *	use the indicated channel.
 *
 * 	Specifying a channel that is ISC_LOG_TONULL for a category/module pair
 *	has no effect on any other channels associated with that pair,
 *	regardless of ordering.  Thus you cannot use it to "mask out" one
 *	category/module pair when you have specified some other channel that
 * 	is also used by that category/module pair.
 *
 * Requires:
 *	lctx is a valid logging context.
 *	
 *	category is NULL or has an id that is in the range of known ids.
 *
 *	module is NULL or has an id that is in the range of known ids.
 *
 * Ensures:
 *	ISC_R_SUCCESS
 *		The channel will be used by the indicated category/module
 *		arguments.
 *
 *	ISC_R_NOMEMORY
 *		If assignment for a specific category has been requested,
 *		the channel has not been associated with the indicated
 *		category/module arguments and no additional memory is
 *		used by the logging context.
 *
 *		If assignment for all categories has been requested
 *		then _some_ may have succeeded (starting with category
 *		"default" and progressing through the order of categories
 *		passed to isc_registercategories) and additional memory
 *		is being used by whatever assignments succeeded.
 *
 * Returns:
 *	ISC_R_SUCCESS	Success
 *	ISC_R_NOMEMORY	Resource limit: Out of memory
 */

void
isc_log_write(isc_log_t *lctx, isc_logcategory_t *category,
	      isc_logmodule_t *module, int level, const char *format, ...);
/*
 * Write a message to the log channels.
 *
 * Notes:
 *	lctx can be NULL; this is allowed so that programs which use
 *	libraries that use the ISC logging system are not required to
 *	also use it.
 *
 *	The format argument is a printf(3) string, with additional arguments
 *	as necessary.
 *
 * Requires:
 *	lctx is a valid logging context.
 *
 *	The category and module arguments must have ids that are in the
 *	range of known ids, as estabished by isc_log_registercategories()
 *	and isc_log_registermodules().
 *
 *	level != ISC_LOG_DYNAMiC.  ISC_LOG_DYNAMIC is used only to define
 *	channels, and explicit debugging level must be identified for
 *	isc_log_write() via ISC_LOG_DEBUG(level).
 *
 *	format != NULL.
 *
 * Ensures:
 *	The log message is written to every channel associated with the
 *	indicated category/module pair.
 *
 * Returns:
 *	Nothing.  Failure to log a message is not construed as a
 *	meaningful error.
 */

void
isc_log_vwrite(isc_log_t *lctx, isc_logcategory_t *category,
	       isc_logmodule_t *module, int level, const char *format,
	       va_list args);
/*
 * Write a message to the log channels.
 *
 * Notes:
 *	lctx can be NULL; this is allowed so that programs which use
 *	libraries that use the ISC logging system are not required to
 *	also use it.
 *
 *	The format argument is a printf(3) string, with additional arguments
 *	as necessary.
 *
 * Requires:
 *	lctx is a valid logging context.
 *
 *	The category and module arguments must have ids that are in the
 *	range of known ids, as estabished by isc_log_registercategories()
 *	and isc_log_registermodules().
 *
 *	level != ISC_LOG_DYNAMiC.  ISC_LOG_DYNAMIC is used only to define
 *	channels, and explicit debugging level must be identified for
 *	isc_log_write() via ISC_LOG_DEBUG(level).
 *
 *	format != NULL.
 *
 * Ensures:
 *	The log message is written to every channel associated with the
 *	indicated category/module pair.
 *
 * Returns:
 *	Nothing.  Failure to log a message is not construed as a
 *	meaningful error.
 */

void
isc_log_write1(isc_log_t *lctx, isc_logcategory_t *category,
	      isc_logmodule_t *module, int level, const char *format, ...);
/*
 * Write a message to the log channels, pruning duplicates that occur within
 * a configurable amount of seconds (see isc_log_[sg]etduplicateinterval).
 * This function is otherwise identical to isc_log_write().
 */

void
isc_log_vwrite1(isc_log_t *lctx, isc_logcategory_t *category,
	       isc_logmodule_t *module, int level, const char *format,
	       va_list args);
/*
 * Write a message to the log channels, pruning duplicates that occur within
 * a configurable amount of seconds (see isc_log_[sg]etduplicateinterval).
 * This function is otherwise identical to isc_log_vwrite().
 */

void
isc_log_setdebuglevel(isc_log_t *lctx, unsigned int level);
/*
 * Set the debugging level used for logging.
 *
 * Notes:
 *	Setting the debugging level to 0 disables debugging log messages.
 *
 * Requires:
 *	lctx is a valid logging context.
 *
 * Ensures:
 *	The debugging level is set to the requested value.
 */

unsigned int
isc_log_getdebuglevel(isc_log_t *lctx);
/*
 * Get the current debugging level.
 *
 * Notes:
 *	This is provided so that a program can have a notion of
 *	"increment debugging level" or "decrement debugging level"
 *	without needing to keep track of what the current level is.
 *
 *	A return value of 0 indicates that debugging messages are disabled.
 *
 * Requires:
 *	lctx is a valid logging context.
 *	
 * Ensures:
 *	The current logging debugging level is returned.
 */

void
isc_log_setduplicateinterval(isc_log_t *lctx, unsigned int interval);
/*
 * Set the interval over which duplicate log messages will be ignored
 * by isc_log_[v]write1(), in seconds.
 *
 * Notes:
 *	Increasing the duplicate interval from X to Y will not necessarily
 *	filter out duplicates of messages logged in Y - X seconds since the
 *	increase.  (Example: Message1 is logged at midnight.  Message2
 *	is logged at 00:01:00, when the interval is only 30 seconds, causing
 *	Message1 to be expired from the log message history.  Then the interval
 *	is increased to 3000 (five minutes) and at 00:04:00 Message1 is logged
 *	again.  It will appear the second time even though less than five
 *	passed since the first occurrence.
 *
 * Requires:
 *	lctx is a valid logging context.
 *
 * Ensures:
 *	The duplicate interval is set to the current	
 */

unsigned int
isc_log_getduplicateinterval(isc_log_t *lctx);
/*
 * Get the current duplicate filtering interval.
 *
 * Requires:
 *	lctx is a valid logging context.
 *
 * Ensures:
 *	The current duplicate filtering interval is returned.
 */

void
isc_log_opensyslog(const char *tag, int options, int facility);
/*
 * Initialize syslog logging.
 *
 * Notes:
 *	XXXDCL NT
 *	This is currently equivalent to openlog(), but is not going to remain
 *	that way.  In the meantime, the arguments are all identical to
 *	those used by openlog(3), as follows:
 *		tag: The string to use in the position of the program
 *			name in syslog messages.  Most (all?) syslogs
 *			will use basename(argv[0]) if tag is NULL.
 *
 *		options: LOG_CONS, LOG_PID, LOG_NDELAY ... whatever your
 *			syslog supports.
 *
 *		facility: The default syslog facility.  This is irrelevant
 *			since isc_log_write will ALWAYS use the channel's
 *			declared facility.
 *
 *	Zero effort has been made (yet) to accomodate systems with openlog()
 *	that only takes two arguments, or to identify valid syslog
 *	facilities or options for any given architecture.
 *
 *	It is necessary to call isc_log_opensyslog() to initialize
 *	syslogging on machines which do not support network connections to
 *	syslogd because they require a Unix domain socket to be used.  Since
 *	this is a chore to determine at run-time, it is suggested that it
 *	always be called by programs using the ISC logging system.
 *
 * Requires:
 *	Nothing.
 *
 * Ensures:
 *	openlog() is called to initialize the syslog system.
 */

void
isc_log_closefilelogs(isc_log_t *lctx);
/*
 * Close all open files used by ISC_LOG_TOFILE channels.
 *
 * Notes:
 *	This function is provided for programs that want to use their own
 *	log rolling mechanism rather than the one provided internally.
 *	For example, a program that wanted to keep daily logs would define
 *	a channel which used ISC_LOG_ROLLNEVER, then once a day would
 *	rename the log file and call isc_log_closefilelogs().
 *
 *	ISC_LOG_TOFILEDESC channels are unaffected.
 *
 * Requires:
 *	lctx is a valid context.
 *
 * Ensures:
 *	The open files are closed and will be reopened when they are
 *	next needed.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_LOG_H */
