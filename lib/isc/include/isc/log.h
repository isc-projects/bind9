/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file isc/log.h */

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h> /* XXXDCL NT */

#include <isc/formatcheck.h>
#include <isc/lang.h>
#include <isc/types.h>
#include <isc/util.h>

typedef struct isc_logconfig isc_logconfig_t; /*%< Log Configuration */

/*@{*/
/*!
 * \brief Severity levels, patterned after Unix's syslog levels.
 *
 */
#define ISC_LOG_DEBUG(level) (level)
/*!
 * #ISC_LOG_DYNAMIC can only be used for defining channels with
 * isc_log_createchannel(), not to specify a level in isc_log_write().
 */
#define ISC_LOG_DYNAMIC	 0
#define ISC_LOG_INFO	 (-1)
#define ISC_LOG_NOTICE	 (-2)
#define ISC_LOG_WARNING	 (-3)
#define ISC_LOG_ERROR	 (-4)
#define ISC_LOG_CRITICAL (-5)
/*@}*/

/*@{*/
/*!
 * \brief Destinations.
 */
#define ISC_LOG_TONULL	   1
#define ISC_LOG_TOSYSLOG   2
#define ISC_LOG_TOFILE	   3
#define ISC_LOG_TOFILEDESC 4
/*@}*/

/*@{*/
/*%
 * Channel flags.
 */
#define ISC_LOG_PRINTTIME     0x00001
#define ISC_LOG_PRINTLEVEL    0x00002
#define ISC_LOG_PRINTCATEGORY 0x00004
#define ISC_LOG_PRINTMODULE   0x00008
#define ISC_LOG_PRINTTAG      0x00010 /* tag and ":" */
#define ISC_LOG_PRINTPREFIX   0x00020 /* tag only, no colon */
#define ISC_LOG_PRINTALL      0x0003F
#define ISC_LOG_BUFFERED      0x00040
#define ISC_LOG_DEBUGONLY     0x01000
#define ISC_LOG_OPENERR	      0x08000 /* internal */
#define ISC_LOG_ISO8601	      0x10000 /* if PRINTTIME, use ISO8601 */
#define ISC_LOG_UTC	      0x20000 /* if PRINTTIME, use UTC */
/*@}*/

/*@{*/
/*!
 * \brief Other options.
 *
 * XXXDCL INFINITE doesn't yet work.  Arguably it isn't needed, but
 *   since I am intend to make large number of versions work efficiently,
 *   INFINITE is going to be trivial to add to that.
 */
#define ISC_LOG_ROLLINFINITE (-1)
#define ISC_LOG_ROLLNEVER    (-2)
#define ISC_LOG_MAX_VERSIONS 256
/*@}*/

/*@{*/
/*!
 * \brief Type of suffix used on rolled log files.
 */
typedef enum {
	isc_log_rollsuffix_increment,
	isc_log_rollsuffix_timestamp
} isc_log_rollsuffix_t;
/*@}*/

/*!
 * \brief Used to name the categories used by a library.
 *
 * An array of isc_logcategory
 * structures names each category, and the id value is initialized by calling
 * isc_log_registercategories.
 */
typedef enum isc_logcategory isc_logcategory_t; /*%< Log Category */
enum isc_logcategory {
	/*%
	 * Logging to DEFAULT will end with assertion failure.  Use another
	 * category.  When in doubt, use GENERAL.
	 */
	ISC_LOGCATEGORY_INVALID = -1,
	/* isc categories */
	ISC_LOGCATEGORY_DEFAULT = 0,
	ISC_LOGCATEGORY_GENERAL,
	DNS_LOGCATEGORY_GENERAL = ISC_LOGCATEGORY_GENERAL,
	NS_LOGCATEGORY_GENERAL = ISC_LOGCATEGORY_GENERAL,
	NAMED_LOGCATEGORY_GENERAL = ISC_LOGCATEGORY_GENERAL,
	ISC_LOGCATEGORY_SSLKEYLOG,
	/* dns categories */
	DNS_LOGCATEGORY_NOTIFY,
	DNS_LOGCATEGORY_DATABASE,
	DNS_LOGCATEGORY_SECURITY,
	DNS_LOGCATEGORY_DNSSEC,
	DNS_LOGCATEGORY_RESOLVER,
	DNS_LOGCATEGORY_XFER_IN,
	DNS_LOGCATEGORY_XFER_OUT,
	DNS_LOGCATEGORY_DISPATCH,
	DNS_LOGCATEGORY_LAME_SERVERS,
	DNS_LOGCATEGORY_EDNS_DISABLED,
	DNS_LOGCATEGORY_RPZ,
	DNS_LOGCATEGORY_RRL,
	DNS_LOGCATEGORY_CNAME,
	DNS_LOGCATEGORY_SPILL,
	DNS_LOGCATEGORY_DNSTAP,
	DNS_LOGCATEGORY_ZONELOAD,
	DNS_LOGCATEGORY_NSID,
	DNS_LOGCATEGORY_RPZ_PASSTHRU,
	/* ns categories */
	NS_LOGCATEGORY_CLIENT,
	NS_LOGCATEGORY_NETWORK,
	NS_LOGCATEGORY_UPDATE,
	NS_LOGCATEGORY_QUERIES,
	NS_LOGCATEGORY_UPDATE_SECURITY,
	NS_LOGCATEGORY_QUERY_ERRORS,
	NS_LOGCATEGORY_TAT,
	NS_LOGCATEGORY_SERVE_STALE,
	NS_LOGCATEGORY_RESPONSES,
	/* cfg categories */
	CFG_LOGCATEGORY_CONFIG,
	/* named categories */
	NAMED_LOGCATEGORY_UNMATCHED,
	/* delv categories */
	DELV_LOGCATEGORY_DEFAULT,

	ISC_LOGCATEGORY_MAX, /*% The number of categories */
	ISC_LOGCATEGORY_MAKE_ENUM_32BIT = INT32_MAX,
};

/*%
 * Similar to isc_logcategory, but for all the modules a library defines.
 */
typedef enum isc_logmodule isc_logmodule_t; /*%< Log Module */
enum isc_logmodule {
	ISC_LOGMODULE_INVALID = -1,
	/* isc modules */
	ISC_LOGMODULE_DEFAULT = 0,
	ISC_LOGMODULE_SOCKET,
	ISC_LOGMODULE_TIME,
	ISC_LOGMODULE_INTERFACE,
	ISC_LOGMODULE_TIMER,
	ISC_LOGMODULE_FILE,
	ISC_LOGMODULE_NETMGR,
	ISC_LOGMODULE_OTHER,
	/* dns modules */
	DNS_LOGMODULE_DB,
	DNS_LOGMODULE_RBTDB,
	DNS_LOGMODULE_RBT,
	DNS_LOGMODULE_RDATA,
	DNS_LOGMODULE_MASTER,
	DNS_LOGMODULE_MESSAGE,
	DNS_LOGMODULE_CACHE,
	DNS_LOGMODULE_CONFIG,
	DNS_LOGMODULE_RESOLVER,
	DNS_LOGMODULE_ZONE,
	DNS_LOGMODULE_JOURNAL,
	DNS_LOGMODULE_ADB,
	DNS_LOGMODULE_XFER_IN,
	DNS_LOGMODULE_XFER_OUT,
	DNS_LOGMODULE_ACL,
	DNS_LOGMODULE_VALIDATOR,
	DNS_LOGMODULE_DISPATCH,
	DNS_LOGMODULE_REQUEST,
	DNS_LOGMODULE_MASTERDUMP,
	DNS_LOGMODULE_TSIG,
	DNS_LOGMODULE_TKEY,
	DNS_LOGMODULE_SDB,
	DNS_LOGMODULE_DIFF,
	DNS_LOGMODULE_HINTS,
	DNS_LOGMODULE_UNUSED1,
	DNS_LOGMODULE_DLZ,
	DNS_LOGMODULE_DNSSEC,
	DNS_LOGMODULE_CRYPTO,
	DNS_LOGMODULE_PACKETS,
	DNS_LOGMODULE_NTA,
	DNS_LOGMODULE_DYNDB,
	DNS_LOGMODULE_DNSTAP,
	DNS_LOGMODULE_SSU,
	DNS_LOGMODULE_QP,
	/* ns modules */
	NS_LOGMODULE_CLIENT,
	NS_LOGMODULE_QUERY,
	NS_LOGMODULE_INTERFACEMGR,
	NS_LOGMODULE_UPDATE,
	NS_LOGMODULE_XFER_IN,
	NS_LOGMODULE_XFER_OUT,
	NS_LOGMODULE_NOTIFY,
	NS_LOGMODULE_HOOKS,
	/* cfg modules */
	CFG_LOGMODULE_PARSER,
	/* named modules */
	NAMED_LOGMODULE_MAIN,
	NAMED_LOGMODULE_SERVER,
	NAMED_LOGMODULE_CONTROL,
	/* delv modules */
	DELV_LOGMODULE_DEFAULT,

	ISC_LOGMODULE_MAX, /*% The number of modules */
	ISC_LOGMODULE_MAKE_ENUM_32BIT = INT32_MAX,
};

/*%
 * The isc_logfile structure is initialized as part of an isc_logdestination
 * before calling isc_log_createchannel().
 *
 * When defining an #ISC_LOG_TOFILE channel, the name, versions and
 * maximum_size should be set before calling isc_log_createchannel().  To
 * define an #ISC_LOG_TOFILEDESC channel set only the stream before the
 * call.
 *
 * Setting maximum_size to zero implies no maximum.
 */
typedef struct isc_logfile {
	FILE *stream;	      /*%< Initialized to NULL for
			       * #ISC_LOG_TOFILE. */
	const char *name;     /*%< NULL for #ISC_LOG_TOFILEDESC. */
	int	    versions; /* >= 0, #ISC_LOG_ROLLNEVER,
			       * #ISC_LOG_ROLLINFINITE. */
	isc_log_rollsuffix_t suffix;
	/*%
	 * stdio's ftell is standardized to return a long, which may well not
	 * be big enough for the largest file supportable by the operating
	 * system (though it is _probably_ big enough for the largest log
	 * anyone would want).  st_size returned by fstat should be typedef'd
	 * to a size large enough for the largest possible file on a system.
	 */
	off_t maximum_size;
	bool  maximum_reached; /*%< Private. */
} isc_logfile_t;

/*%
 * Passed to isc_log_createchannel to define the attributes of either
 * a stdio or a syslog log.
 */
typedef union isc_logdestination {
	isc_logfile_t file;
	int	      facility;
} isc_logdestination_t;

#define ISC_LOGDESTINATION_FILE(errout)                         \
	(&(isc_logdestination_t){                               \
		.file = {                                       \
			.stream = errout,                       \
			.versions = ISC_LOG_ROLLNEVER,          \
			.suffix = isc_log_rollsuffix_increment, \
		} })

#define ISC_LOGDESTINATION_STDERR ISC_LOGDESTINATION_FILE(stderr)

#define ISC_LOGDESTINATION_SYSLOG(f) \
	(&(isc_logdestination_t){ .facility = (f) })

/*@{*/
/*%
 * The built-in categories of libisc.
 *
 * Each library registering categories should provide library_LOGCATEGORY_name
 * definitions with indexes into its isc_logcategory structure corresponding to
 * the order of the names.
 */
extern isc_logcategory_t isc_categories[];
extern isc_logmodule_t	 isc_modules[];
/*@}*/

ISC_LANG_BEGINDECLS

void
isc_logconfig_create(isc_logconfig_t **lcfgp);
/*%<
 * Create the data structure that holds all of the configurable information
 * about where messages are actually supposed to be sent -- the information
 * that could changed based on some configuration file, as opposed to the
 * the category/module specification of isc_log_[v]write[1] that is compiled
 * into a program, or the debug_level which is dynamic state information.
 *
 * Notes:
 *\li	It is necessary to specify the logging context the configuration
 * 	will be used with because the number of categories and modules
 *	needs to be known in order to set the configuration.  However,
 *	the configuration is not used by the logging context until the
 *	isc_logconfig_use function is called.
 *
 *\li	The memory context used for operations that allocate memory for
 *	the configuration is that of the logging context, as specified
 *	in the isc_log_create call.
 *
 *\li	Four default channels are established:
 *\verbatim
 *	    	default_syslog
 *		 - log to syslog's daemon facility #ISC_LOG_INFO or higher
 *		default_stderr
 *		 - log to stderr #ISC_LOG_INFO or higher
 *		default_debug
 *		 - log to stderr #ISC_LOG_DEBUG dynamically
 *		null
 *		 - log nothing
 *\endverbatim
 *
 * Requires:
 *\li 	lctx is a valid logging context.
 *\li	lcftp is not null and *lcfgp is null.
 *
 * Ensures:
 *\li	*lcfgp will point to a valid logging context if all of the necessary
 *	memory was allocated, or NULL otherwise.
 *\li	On failure, no additional memory is allocated.
 */

isc_logconfig_t *
isc_logconfig_get(void);
void
isc_logconfig_set(isc_logconfig_t *lcfg);
/*%<
 * Getter/setter for a configuration with a logging context.
 *
 * Notes:
 *\li	The setter is thread safe.  The getter is only thread-safe
 *	if the isc_logconfig_get() call is protected by RCU read-lock.
 *
 * Requires:
 *\li	lctx is a valid logging context.
 *\li	lcfg is a valid logging configuration.
 *\li	lctx is the same configuration given to isc_logconfig_create
 *		when the configuration was created.
 *
 * Ensures:
 *\li	Future calls to isc_log_write will use the new configuration.
 *\li	The previous configuration object will be destroyed.
 */

void
isc_logconfig_destroy(isc_logconfig_t **lcfgp);
/*%<
 * Destroy a logging configuration.
 *
 * Requires:
 *\li	lcfgp is not null and *lcfgp is a valid logging configuration.
 *\li	The logging configuration is not in use by an existing logging context.
 *
 * Ensures:
 *\li	All memory allocated for the configuration is freed.
 *
 *\li	The configuration is marked as invalid.
 */

void
isc_log_createchannel(isc_logconfig_t *lcfg, const char *name,
		      unsigned int type, int level,
		      const isc_logdestination_t *destination,
		      unsigned int		  flags);
/*%<
 * Specify the parameters of a logging channel.
 *
 * Notes:
 *\li	The name argument is copied to memory in the logging context, so
 *	it can be altered or destroyed after isc_log_createchannel().
 *
 *\li	Defining a very large number of channels will have a performance
 *	impact on isc_log_usechannel(), since the names are searched
 *	linearly until a match is made.  This same issue does not affect
 *	isc_log_write, however.
 *
 *\li	Channel names can be redefined; this is primarily useful for programs
 *	that want their own definition of default_syslog, default_debug
 *	and default_stderr.
 *
 *\li	Any channel that is redefined will not affect logging that was
 *	already directed to its original definition, _except_ for the
 *	default_stderr channel.  This case is handled specially so that
 *	the default logging category can be changed by redefining
 *	default_stderr.  (XXXDCL Though now that I think of it, the default
 *	logging category can be changed with only one additional function
 *	call by defining a new channel and then calling isc_log_usechannel()
 *	for #ISC_LOGCATEGORY_DEFAULT.)
 *
 *\li	Specifying #ISC_LOG_PRINTTIME or #ISC_LOG_PRINTTAG for syslog is
 *	allowed, but probably not what you wanted to do.
 *
 *	#ISC_LOG_DEBUGONLY will mark the channel as usable only when the
 *	debug level of the logging context (see isc_log_setdebuglevel)
 *	is non-zero.
 *
 * Requires:
 *\li	lcfg is a valid logging configuration.
 *
 *\li	name is not NULL.
 *
 *\li	type is #ISC_LOG_TOSYSLOG, #ISC_LOG_TOFILE, #ISC_LOG_TOFILEDESC or
 *		#ISC_LOG_TONULL.
 *
 *\li	destination is not NULL unless type is #ISC_LOG_TONULL.
 *
 *\li	level is >= #ISC_LOG_CRITICAL (the most negative logging level).
 *
 *\li	flags does not include any bits aside from the ISC_LOG_PRINT* bits,
 *	#ISC_LOG_DEBUGONLY or #ISC_LOG_BUFFERED.
 *
 * Ensures:
 *\li	#ISC_R_SUCCESS
 *		A channel with the given name is usable with
 *		isc_log_usechannel().
 *
 *\li	#ISC_R_NOMEMORY or #ISC_R_UNEXPECTED
 *		No additional memory is being used by the logging context.
 *		Any channel that previously existed with the given name
 *		is not redefined.
 */

isc_result_t
isc_log_usechannel(isc_logconfig_t *lcfg, const char *name,
		   const isc_logcategory_t category,
		   const isc_logmodule_t   module);
/*%<
 * Associate a named logging channel with a category and module that
 * will use it.
 *
 * Notes:
 *\li	The name is searched for linearly in the set of known channel names
 *	until a match is found.  (Note the performance impact of a very large
 *	number of named channels.)  When multiple channels of the same
 *	name are defined, the most recent definition is found.
 *
 *\li	Specifying a very large number of channels for a category will have
 *	a moderate impact on performance in isc_log_write(), as each
 *	call looks up the category for the start of a linked list, which
 *	it follows all the way to the end to find matching modules.  The
 *	test for matching modules is  integral, though.
 *
 *\li	If category is NULL, then the channel is associated with the indicated
 *	module for all known categories (including the "default" category).
 *
 *\li	If module is NULL, then the channel is associated with every module
 *	that uses that category.
 *
 *\li	Passing both category and module as NULL would make every log message
 *	use the indicated channel.
 *
 * \li	Specifying a channel that is #ISC_LOG_TONULL for a category/module pair
 *	has no effect on any other channels associated with that pair,
 *	regardless of ordering.  Thus you cannot use it to "mask out" one
 *	category/module pair when you have specified some other channel that
 * 	is also used by that category/module pair.
 *
 * Requires:
 *\li	lcfg is a valid logging configuration.
 *
 *\li	category is ISC_LOGCATEGORY_DEFAULT or has an id that is in the range of
 *	known ids.
 *
 *	module is ISC_LOGMODULE_DEFAULT or has an id that is in the range of
 *	known ids.
 *
 * Ensures:
 *	The channel will be used by the indicated category/module
 *	arguments.
 */

void
isc_log_createandusechannel(isc_logconfig_t *lcfg, const char *name,
			    unsigned int type, int level,
			    const isc_logdestination_t *destination,
			    unsigned int		flags,
			    const isc_logcategory_t	category,
			    const isc_logmodule_t	module);

/*%<
 * The isc_log_createchannel() and isc_log_usechannel() functions, combined
 * into one.  (This is for use by utilities that have simpler logging
 * requirements than named, and don't have to define and assign channels
 * dynamically.)
 */

void
isc_log_write(isc_logcategory_t category, isc_logmodule_t module, int level,
	      const char *format, ...) ISC_FORMAT_PRINTF(4, 5);
/*%<
 *   \brief
 * Write a message to the log channels.
 *
 * Notes:
 *\li	The format argument is a printf(3) string, with additional arguments
 *	as necessary.
 *
 * Requires:
 *\li	The category and module arguments must have ids that are in the
 *	range of known ids.
 *
 *\li	category != ISC_LOGCATEGORY_DEFAULT.  ISC_LOGCATEGORY_DEFAULT is used
 *	only to define channels.
 *
 *\li	module != ISC_LOGMODULE_DEFAULT.  ISC_LOGMODULE_DEFAULT is used
 *	only to define channels.
 *
 *\li	level != #ISC_LOG_DYNAMIC.  ISC_LOG_DYNAMIC is used only to define
 *	channels, and explicit debugging level must be identified for
 *	isc_log_write() via ISC_LOG_DEBUG(level).
 *
 *\li	format != NULL.
 *
 * Ensures:
 *\li	The log message is written to every channel associated with the
 *	indicated category/module pair.
 *
 * Returns:
 *\li	Nothing.  Failure to log a message is not construed as a
 *	meaningful error.
 */

void
isc_log_vwrite(isc_logcategory_t category, isc_logmodule_t module, int level,
	       const char *format, va_list args) ISC_FORMAT_PRINTF(4, 0);
/*%<
 * Write a message to the log channels.
 *
 *\li	The format argument is a printf(3) string, with additional arguments
 *	as necessary.
 *
 * Requires:
 *\li	The category and module arguments must have ids that are in the
 *	range of known ids.
 *
 *\li	category != ISC_LOGCATEGORY_DEFAULT.  ISC_LOGCATEGORY_DEFAULT is used
 *	only to define channels.
 *
 *\li	module != ISC_LOGMODULE_DEFAULT.  ISC_LOGMODULE_DEFAULT is used
 *	only to define channels.
 *
 *\li	level != #ISC_LOG_DYNAMIC.  ISC_LOG_DYNAMIC is used only to define
 *	channels, and explicit debugging level must be identified for
 *	isc_log_write() via ISC_LOG_DEBUG(level).
 *
 *\li	format != NULL.
 *
 * Ensures:
 *\li	The log message is written to every channel associated with the
 *	indicated category/module pair.
 *
 * Returns:
 *\li	Nothing.  Failure to log a message is not construed as a
 *	meaningful error.
 */

void
isc_log_setdebuglevel(unsigned int level);
/*%<
 * Set the debugging level used for logging.
 *
 * Notes:
 *\li	Setting the debugging level to 0 disables debugging log messages.
 *
 * Requires:
 *\li	lctx is a valid logging context.
 *
 * Ensures:
 *\li	The debugging level is set to the requested value.
 */

unsigned int
isc_log_getdebuglevel(void);
/*%<
 * Get the current debugging level.
 *
 * Notes:
 *\li	This is provided so that a program can have a notion of
 *	"increment debugging level" or "decrement debugging level"
 *	without needing to keep track of what the current level is.
 *
 *\li	A return value of 0 indicates that debugging messages are disabled.
 *
 * Requires:
 *\li	lctx is a valid logging context.
 *
 * Ensures:
 *\li	The current logging debugging level is returned.
 */

bool
isc_log_wouldlog(int level);
/*%<
 * Determine whether logging something to 'lctx' at 'level' would
 * actually cause something to be logged somewhere.
 *
 * If #false is returned, it is guaranteed that nothing would
 * be logged, allowing the caller to omit unnecessary
 * isc_log_write() calls and possible message preformatting.
 */

void
isc_log_settag(isc_logconfig_t *lcfg, const char *tag);
/*%<
 * Set the program name or other identifier for #ISC_LOG_PRINTTAG.
 *
 * Requires:
 *\li	lcfg is a valid logging configuration.
 *
 * Notes:
 *\li	If this function has not set the tag to a non-NULL, non-empty value,
 *	then the #ISC_LOG_PRINTTAG channel flag will not print anything.
 *	Unlike some implementations of syslog on Unix systems, you *must* set
 *	the tag in order to get it logged.  It is not implicitly derived from
 *	the program name (which is pretty impossible to infer portably).
 *
 *\li	Setting the tag to NULL or the empty string will also cause the
 *	#ISC_LOG_PRINTTAG channel flag to not print anything.  If tag equals the
 *	empty string, calls to isc_log_gettag will return NULL.
 *
 * XXXDCL when creating a new isc_logconfig_t, it might be nice if the tag
 * of the currently active isc_logconfig_t was inherited.  this does not
 * currently happen.
 */

char *
isc_log_gettag(isc_logconfig_t *lcfg);
/*%<
 * Get the current identifier printed with #ISC_LOG_PRINTTAG.
 *
 * Requires:
 *\li	lcfg is a valid logging configuration.
 *
 * Notes:
 *\li	Since isc_log_settag() will not associate a zero-length string
 *	with the logging configuration, attempts to do so will cause
 *	this function to return NULL.  However, a determined programmer
 *	will observe that (currently) a tag of length greater than zero
 *	could be set, and then modified to be zero length.
 *
 * Returns:
 *\li	A pointer to the current identifier, or NULL if none has been set.
 */

void
isc_log_opensyslog(const char *tag, int options, int facility);
/*%<
 * Initialize syslog logging.
 *
 * Notes:
 *\li	XXXDCL NT
 *	This is currently equivalent to openlog(), but is not going to remain
 *	that way.  In the meantime, the arguments are all identical to
 *	those used by openlog(3), as follows:
 *
 * \code
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
 * \endcode
 *
 *\li	Zero effort has been made (yet) to accommodate systems with openlog()
 *	that only takes two arguments, or to identify valid syslog
 *	facilities or options for any given architecture.
 *
 *\li	It is necessary to call isc_log_opensyslog() to initialize
 *	syslogging on machines which do not support network connections to
 *	syslogd because they require a Unix domain socket to be used.  Since
 *	this is a chore to determine at run-time, it is suggested that it
 *	always be called by programs using the ISC logging system.
 *
 * Requires:
 *\li	Nothing.
 *
 * Ensures:
 *\li	openlog() is called to initialize the syslog system.
 */

void
isc_log_closefilelogs(void);
/*%<
 * Close all open files used by #ISC_LOG_TOFILE channels.
 *
 * Notes:
 *\li	This function is provided for programs that want to use their own
 *	log rolling mechanism rather than the one provided internally.
 *	For example, a program that wanted to keep daily logs would define
 *	a channel which used #ISC_LOG_ROLLNEVER, then once a day would
 *	rename the log file and call isc_log_closefilelogs().
 *
 *\li	#ISC_LOG_TOFILEDESC channels are unaffected.
 *
 * Requires:
 *\li	lctx is a valid context.
 *
 * Ensures:
 *\li	The open files are closed and will be reopened when they are
 *	next needed.
 */

isc_logcategory_t
isc_log_categorybyname(const char *name);
/*%<
 * Find a category by its name.
 *
 * Notes:
 *\li	The string name of a category is not required to be unique.
 *
 * Requires:
 *\li	lctx is a valid context.
 *\li	name is not NULL.
 *
 * Returns:
 *\li	A pointer to the _first_ isc_logcategory_t structure used by "name".
 *
 *\li	NULL if no category exists by that name.
 */

isc_result_t
isc_logfile_roll(isc_logfile_t *file);
/*%<
 * Roll a logfile.
 *
 * Requires:
 *\li	file is not NULL.
 */

void
isc_log_setforcelog(bool v);
/*%<
 * Turn forced logging on/off for the current thread. This can be used to
 * temporarily increase the debug level to maximum for the duration of
 * a single task event.
 */

void
isc__log_initialize(void);
void
isc__log_shutdown(void);
/*%<
 * Library constructor/destructor
 */

ISC_LANG_ENDDECLS
