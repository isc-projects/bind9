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

/* $Id: log.c,v 1.15 2000/02/03 23:08:25 halley Exp $ */

/* Principal Authors: DCL */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/dir.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/print.h>
#include <isc/time.h>

#define LOG_MAGIC		0x494C4F47U	/* ILOG. */
#define VALID_CONTEXT(lctx)	((lctx) != NULL && (lctx)->magic == LOG_MAGIC)

#define LOG_BUFFER_SIZE	(8 * 1024)

typedef struct isc_logchannel isc_logchannel_t;

/*
 * This is the structure that holds each named channel.  A simple linked
 * list chains all of the channels together, so an individual channel is
 * found by doing strcmp()s with the names down the list.  Their should
 * be no peformance penalty from this as it is expected that the number
 * of named channels will be no more than a dozen or so, and name lookups
 * from the head of the list are only done when isc_log_usechannel() is
 * called, which should also be very infrequent.
 */
struct isc_logchannel {
	char *			name;
	unsigned int		type;
	int 			level;
	unsigned int		flags;
	isc_logdestination_t 	destination;
	isc_logchannel_t *	next;
};

/*
 * The logchannelist structure associates categories and modules with
 * channels.  First the appropriate channellist is found based on the
 * category, and then each structure in the linked list is checked for
 * a matching module.  It is expected that the number of channels
 * associated with any given category will be very short, no more than
 * three or four in the more unusual cases.
 */
typedef struct isc_logchannellist isc_logchannellist_t;

struct isc_logchannellist {
	isc_logmodule_t *	module;
	isc_logchannel_t *	channel;
	isc_logchannellist_t *	next;
};

/*
 * This structure is used to remember messages for pruning via
 * isc_log_[v]write1().
 */
typedef struct isc_logmessage isc_logmessage_t;

struct isc_logmessage {
	char *			text;
	isc_time_t		time;
	isc_logmessage_t *	next;
};

/*
 * This isc_log structure provides the context for the isc_log functions.
 * The log context locks itself in isc_log_vwrite, the internal backend to
 * isc_log_write.  The locking is necessary both to provide exclusive access
 * to the the buffer into which the message is formatted and to guard against
 * competing threads trying to write to the same syslog resource.  (On
 * some systems, such as BSD/OS, stdio is thread safe but syslog is not.)
 * Unfortunately, the lock cannot guard against a _different_ logging
 * context in the same program competing for syslog's attention.  Thus
 * There Can Be Only One, but this is not enforced.
 * XXX enforce it?
 */
struct isc_log {
	unsigned int			magic;
	isc_mem_t *			mctx;
	isc_mutex_t			lock;
	char 				buffer[LOG_BUFFER_SIZE];
	int				debug_level;
	unsigned int			duplicate_interval;
	isc_logchannel_t *		channels;
	isc_logchannellist_t **		categories;
	unsigned int			category_count;
	isc_logmodule_t **		modules;
	unsigned int			module_count;
	ISC_LIST(isc_logmessage_t)	messages;
};

/*
 * Used when ISC_LOG_PRINTLEVEL is enabled for a channel.
 */
static char *log_level_strings[] = {
	"debug", "info", "notice", "warning", "error", "critical"
};

/*
 * Used to convert ISC_LOG_* priorities into syslog priorities.
 * XXXDCL NT
 */
static const int syslog_map[] = {
	LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING, LOG_ERR, LOG_CRIT
};

/*
 * When adding new categories, a corresponding ISC_LOGCATEGORY_foo
 * definition needs to be added to <isc/log.h>.  Each name string should
 * end with a colon-space pair because they are used in the formatted
 * log message when ISC_LOG_PRINTCATEGORY is enabled.
 *
 * The default category is provided so that the internal default can
 * be overridden.  Since the default is always looked up as the first
 * channellist in the log context, it must come first in isc_categories[].
 */
isc_logcategory_t isc_categories[] = {
	{ "default", 0 },	/* "default" must come first. */
	{ NULL, 0 }
};

/*
 * This essentially static structure must be filled in at run time,
 * so that the default_debug channel's structure can be addressed.
 */
isc_logchannellist_t default_channel;

/*
 * Forward declarations.
 */
static isc_result_t
assignchannel(isc_log_t *lctx, unsigned int category_id,
	      isc_logmodule_t *module, isc_logchannel_t *channel);

static unsigned int
greatest_version(isc_logchannel_t *channel);

static isc_result_t
roll_log(isc_logchannel_t *channel);

static void
isc_log_doit(isc_log_t *lctx, isc_logcategory_t *category,
	     isc_logmodule_t *module, int level, isc_boolean_t write_once,
	     const char *format, va_list args);

/*
 * Convenience macros.
 */

#define FACILITY(channel)	(channel->destination.facility)
#define FILE_NAME(channel)	(channel->destination.file.name)
#define FILE_STREAM(channel)	(channel->destination.file.stream)
#define FILE_VERSIONS(channel)	(channel->destination.file.versions)
#define FILE_MAXSIZE(channel)	(channel->destination.file.maximum_size)

/****
 **** Public interfaces.
 ****/

/*
 * Establish a new logging context, with default channels.
 */
isc_result_t
isc_log_create(isc_mem_t *mctx, isc_log_t **lctxp) {
	isc_log_t *lctx;
	isc_logdestination_t destination;
	isc_result_t result;

	REQUIRE(mctx != NULL);
	REQUIRE(lctxp != NULL && *lctxp == NULL);

	lctx = (isc_log_t *)isc_mem_get(mctx, sizeof(*lctx));
	if (lctx == NULL)
		return (ISC_R_NOMEMORY);

	lctx->mctx = mctx;
	lctx->channels = NULL;
	lctx->categories = NULL;
	lctx->category_count = 0;
	lctx->debug_level = 0;
	lctx->duplicate_interval = 0;
	lctx->modules = NULL;
	lctx->module_count = 0;

	ISC_LIST_INIT(lctx->messages);

	result = isc_mutex_init(&lctx->lock);
	
	/*
	 * Normally the magic number is the last thing set in the structure,
	 * but isc_log_createchannel() needs a valid context.  If the channel
	 * creation fails, the lctx is not returned to the caller.
	 */
	lctx->magic = LOG_MAGIC;

	/*
	 * Create the default channels:
	 *   	default_syslog, default_stderr, default_debug and null.
	 */
	if (result == ISC_R_SUCCESS) {
		destination.facility = LOG_INFO;
		result = isc_log_createchannel(lctx, "default_syslog",
					       ISC_LOG_TOSYSLOG, ISC_LOG_INFO,
					       &destination, 0);
	}

	if (result == ISC_R_SUCCESS) {
		destination.file.stream = stderr;
		destination.file.name = NULL;
		destination.file.versions = ISC_LOG_ROLLNEVER;
		destination.file.maximum_size = 0;
		result = isc_log_createchannel(lctx, "default_stderr",
					       ISC_LOG_TOFILEDESC,
					       ISC_LOG_INFO,
					       &destination,
					       ISC_LOG_PRINTTIME);
	}

	/*
	 * Set the default category's channel to default_stderr.
	 * XXX I find this odd.
	 */
	default_channel.channel = lctx->channels;

	if (result == ISC_R_SUCCESS) {
		destination.file.stream = stderr;
		destination.file.name = NULL;
		destination.file.versions = ISC_LOG_ROLLNEVER;
		destination.file.maximum_size = 0;
		result = isc_log_createchannel(lctx, "default_debug",
					       ISC_LOG_TOFILEDESC,
					       ISC_LOG_DYNAMIC,
					       &destination,
					       ISC_LOG_PRINTTIME);
	}

	if (result == ISC_R_SUCCESS)
		result = isc_log_createchannel(lctx, "null",
					       ISC_LOG_TONULL,
					       ISC_LOG_DYNAMIC,
					       NULL, 0);

	if (result == ISC_R_SUCCESS)
		result = isc_log_registercategories(lctx, isc_categories);

	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, lctx, sizeof(*lctx));
		return (result);
	}

	*lctxp = lctx;

	return (ISC_R_SUCCESS);
}

void
isc_log_destroy(isc_log_t **lctxp) {
	isc_log_t *lctx;
	isc_mem_t *mctx;
	isc_logchannel_t *channel, *next_channel;
	isc_logchannellist_t *channellist, *next_channellist;
	isc_logmessage_t *message, *next_message;
	unsigned int i;

	REQUIRE(lctxp != NULL && VALID_CONTEXT(*lctxp));

	lctx = *lctxp;
	mctx = lctx->mctx;

	for (channel = lctx->channels; channel != NULL;
	     channel = next_channel) {
		next_channel = channel->next;

		if (channel->type == ISC_LOG_TOFILE) {
		    isc_mem_free(mctx, FILE_NAME(channel));

		    if (FILE_STREAM(channel) != NULL)
			(void)fclose(FILE_STREAM(channel));
		}

		isc_mem_free(mctx, channel->name);
		isc_mem_put(mctx, channel, sizeof(*channel));
	}

	for (i = 0; i < lctx->category_count; i++)
		for (channellist = lctx->categories[i]; channellist != NULL;
		     channellist = next_channellist) {
		     next_channellist = channellist->next;
		     isc_mem_put(mctx, channellist, sizeof(*channellist));
		}

	isc_mem_put(mctx, &lctx->categories[0],
		    lctx->category_count * sizeof(isc_logchannellist_t **));

	for (message = ISC_LIST_HEAD(lctx->messages); message != NULL;
	     message = next_message) {

	     next_message = message->next;
	     isc_mem_put(mctx, message,
			 sizeof(*message) + strlen(message->text) + 1);
	}
	ISC_LIST_INIT(lctx->messages);

	isc_mutex_destroy(&lctx->lock);

	lctx->magic = 0;

	isc_mem_put(mctx, lctx, sizeof(*lctx));

	*lctxp = NULL;
}

isc_result_t
isc_log_registercategories(isc_log_t *lctx, isc_logcategory_t categories[]) {
	isc_logchannellist_t **lists;
	isc_logcategory_t *catp;
	unsigned int old_count, new_count, bytes;

	REQUIRE(VALID_CONTEXT(lctx));
	REQUIRE(categories != NULL);

	old_count = lctx->category_count;

	/*
	 * Total the number of categories that will exist when these are added.
	 * Update the id number of the category with its new global id.
	 */
	for (new_count = old_count, catp = categories; catp->name != NULL; )
		catp++->id = new_count++;

	lists = (isc_logchannellist_t **)isc_mem_get(lctx->mctx,
				new_count * sizeof(isc_logchannellist_t *));
	if (lists == NULL)
		return (ISC_R_NOMEMORY);

	memset(lists, 0, new_count * sizeof(isc_logchannellist_t *));

	if (old_count != 0) {
		bytes = old_count * sizeof(isc_logchannellist_t *);
		memcpy(lists, lctx->categories, bytes);
		isc_mem_put(lctx->mctx, lctx->categories, bytes);
	}

	lctx->categories = lists;
	lctx->category_count = new_count;

	return (ISC_R_SUCCESS);
}

void
isc_log_registermodules(isc_log_t *lctx, isc_logmodule_t modules[]) {
	isc_logmodule_t *modp;
	unsigned int old_count, new_count;

	REQUIRE(VALID_CONTEXT(lctx));
	REQUIRE(modules != NULL);

	old_count = lctx->module_count;

	/*
	 * Total the number of modules that will exist when these are added.
	 * Update the id number of the module with its new global id.
	 */
	for (new_count = old_count, modp = modules; modp->name != NULL; )
		modp++->id = new_count++;

	lctx->module_count = new_count;
}

isc_result_t
isc_log_createchannel(isc_log_t *lctx, const char *name, unsigned int type,
		      int level, isc_logdestination_t *destination,
		      unsigned int flags)
{
	isc_logchannel_t *channel;

	REQUIRE(VALID_CONTEXT(lctx));
	REQUIRE(name != NULL);
	REQUIRE(type == ISC_LOG_TOSYSLOG   || type == ISC_LOG_TOFILE ||
		type == ISC_LOG_TOFILEDESC || type == ISC_LOG_TONULL);
	REQUIRE(destination != NULL || type == ISC_LOG_TONULL);
	REQUIRE(level >= ISC_LOG_CRITICAL);
	REQUIRE((flags & ~ISC_LOG_PRINTALL) == 0);

	/* XXX DCL find duplicate names? */

	channel = (isc_logchannel_t *)isc_mem_get(lctx->mctx,
						  sizeof(*channel));
	if (channel == NULL)
		return (ISC_R_NOMEMORY);

	channel->name = isc_mem_strdup(lctx->mctx, name);
	if (channel->name == NULL) {
		isc_mem_put(lctx->mctx, channel, sizeof(*channel));
		return (ISC_R_NOMEMORY);
	}

	channel->type = type;
	channel->level = level;
	channel->flags = flags;

	switch (type) {
	case ISC_LOG_TOSYSLOG:
		FACILITY(channel) = destination->facility;
		break;

	case ISC_LOG_TOFILE:
		/*
		 * The file name is copied because greatest_version wants
		 * to scribble on it, so it needs to be definitely in
		 * writable memory.
		 */
		FILE_NAME(channel) =
			isc_mem_strdup(lctx->mctx, destination->file.name);
		FILE_STREAM(channel) = NULL;
		FILE_MAXSIZE(channel) = destination->file.maximum_size;
		FILE_VERSIONS(channel) = destination->file.versions;
		break;

	case ISC_LOG_TOFILEDESC:
		FILE_NAME(channel) = NULL;
		FILE_STREAM(channel) = destination->file.stream;
		FILE_MAXSIZE(channel) = 0;
		FILE_VERSIONS(channel) = ISC_LOG_ROLLNEVER;
		break;

	case ISC_LOG_TONULL:
		/* Nothing. */
		break;

	default:
		isc_mem_put(lctx->mctx, channel->name,
			    strlen(channel->name) + 1);
		isc_mem_put(lctx->mctx, channel, sizeof(*channel));
		return (ISC_R_UNEXPECTED);
	}
	
	channel->next = lctx->channels;
	lctx->channels = channel;

	/*
	 * If default_stderr was redefined, make the default category
	 * point to the new default_stderr.
	 * XXX I find this odd.
	 */
	if (strcmp(name, "default_stderr") == 0)
		default_channel.channel = channel;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_log_usechannel(isc_log_t *lctx, const char *name,
		   isc_logcategory_t *category, isc_logmodule_t *module)
{
	isc_logchannel_t *channel;
	isc_result_t result;
	unsigned int i;

	REQUIRE(VALID_CONTEXT(lctx));
	REQUIRE(name != NULL);
	REQUIRE(category == NULL || category->id < lctx->category_count);
	REQUIRE(module == NULL || module->id < lctx->module_count);

	for (channel = lctx->channels; channel != NULL;
	     channel = channel->next)
		if (strcmp(name, channel->name) == 0)
			break;

	if (channel == NULL)
		return (ISC_R_NOTFOUND);

	/*
	 * Silence bogus GCC warning, "`result' might be used uninitialized".
	 */
	result = ISC_R_SUCCESS;

	if (category != NULL)
		result = assignchannel(lctx, category->id, module, channel);

	else
		/*
		 * Assign to all categories.  Note that this includes
		 * the default channel.
		 */
		for (i = 0; i < lctx->category_count; i++) {
			result = assignchannel(lctx, i, module, channel);
			if (result != ISC_R_SUCCESS)
				break;
		}

	return (result);
}

void
isc_log_write(isc_log_t *lctx, isc_logcategory_t *category,
	      isc_logmodule_t *module, int level, const char *format, ...)

{
	va_list args;

	/*
	 * Contract checking is done in isc_log_doit().
	 */

	va_start(args, format);
	isc_log_doit(lctx, category, module, level, ISC_FALSE, format, args);
	va_end(args);
}

void
isc_log_vwrite(isc_log_t *lctx, isc_logcategory_t *category,
	       isc_logmodule_t *module, int level,
	       const char *format, va_list args)

{
	/*
	 * Contract checking is done in isc_log_doit().
	 */
	isc_log_doit(lctx, category, module, level, ISC_FALSE, format, args);
}

void
isc_log_write1(isc_log_t *lctx, isc_logcategory_t *category,
	       isc_logmodule_t *module, int level, const char *format, ...)

{
	va_list args;

	/*
	 * Contract checking is done in isc_log_doit().
	 */

	va_start(args, format);
	isc_log_doit(lctx, category, module, level, ISC_TRUE, format, args);
	va_end(args);
}

void
isc_log_vwrite1(isc_log_t *lctx, isc_logcategory_t *category,
		isc_logmodule_t *module, int level,
		const char *format, va_list args)

{
	/*
	 * Contract checking is done in isc_log_doit().
	 */
	isc_log_doit(lctx, category, module, level, ISC_TRUE, format, args);
}

void
isc_log_setdebuglevel(isc_log_t *lctx, unsigned int level) {
	REQUIRE(VALID_CONTEXT(lctx));

	lctx->debug_level = level;
}

unsigned int
isc_log_getdebuglevel(isc_log_t *lctx) {
	REQUIRE(VALID_CONTEXT(lctx));

	return (lctx->debug_level);
}

void
isc_log_setduplicateinterval(isc_log_t *lctx, unsigned int interval) {
	REQUIRE(VALID_CONTEXT(lctx));

	lctx->duplicate_interval = interval;
}

unsigned int
isc_log_getduplicateinterval(isc_log_t *lctx) {
	REQUIRE(VALID_CONTEXT(lctx));

	return (lctx->duplicate_interval);
}

/* XXXDCL NT  -- This interface will assuredly be changing. */
void
isc_log_opensyslog(const char *tag, int options, int facility) {
	openlog(tag, options, facility);
}

void
isc_log_closefilelogs(isc_log_t *lctx) {
	isc_logchannel_t *channel;

	REQUIRE(VALID_CONTEXT(lctx));

	for (channel = lctx->channels; channel != NULL; channel= channel->next)
		if (channel->type == ISC_LOG_TOFILE &&
		    FILE_STREAM(channel) != NULL) {
			(void)fclose(FILE_STREAM(channel));
			FILE_STREAM(channel) = NULL;
		}
}

/****
 **** Internal functions
 ****/

static isc_result_t
assignchannel(isc_log_t *lctx, unsigned int category_id,
	      isc_logmodule_t *module, isc_logchannel_t *channel)
{
	isc_logchannellist_t *new_item;

	REQUIRE(VALID_CONTEXT(lctx));
	REQUIRE(category_id < lctx->category_count);
	REQUIRE(module == NULL || module->id < lctx->module_count);
	REQUIRE(channel != NULL);

	new_item = (isc_logchannellist_t *)isc_mem_get(lctx->mctx,
						       sizeof(*new_item));
	if (new_item == NULL)
		return (ISC_R_NOMEMORY);

	new_item->channel = channel;
	new_item->module = module;
	new_item->next = lctx->categories[category_id];

	lctx->categories[category_id] = new_item;

	return (ISC_R_SUCCESS);
}

static unsigned int
greatest_version(isc_logchannel_t *channel)
{
	/* XXXDCL HIGHLY NT */
	char *dirname, *basename, *digit_end;
	int version, greatest = -1;
	unsigned int basenamelen;
	isc_dir_t dir;
	isc_result_t result;

	REQUIRE(channel->type == ISC_LOG_TOFILE);

	basename = strrchr(FILE_NAME(channel), '/');
	if (basename != NULL) {
		*basename++ = '\0';
		dirname = FILE_NAME(channel);
	} else {
		basename = FILE_NAME(channel);
		dirname = ".";
	}
	basenamelen = strlen(basename);


	isc_dir_init(&dir);
	result = isc_dir_open(&dir, dirname);
	if (result != ISC_R_SUCCESS)
		return (0); /* ... and roll_log will likely report an error. */

	while (isc_dir_read(&dir) == ISC_R_SUCCESS) {
		if (dir.entry.length > basenamelen &&
		    strncmp(dir.entry.name, basename, basenamelen) == 0 &&
		    dir.entry.name[basenamelen] == '.') {

			version = strtol(&dir.entry.name[basenamelen + 1],
					  &digit_end, 10);
			if (*digit_end == '\0' && version > greatest)
				greatest = version;
		}
	}

	if (basename != FILE_NAME(channel))
		*--basename = '/';

	return (++greatest);
}

static isc_result_t
roll_log(isc_logchannel_t *channel) {
	int i, greatest, digits = 0;
	char current[FILENAME_MAX + 1];
	char new[FILENAME_MAX + 1];
	char *path;

	/*
	 * XXXDCL versions = 0 & versions == ISC_LOG_ROLLINFINITE do not work.
	 */
	/*
	 * Do nothing (not even excess version trimming) if ISC_LOG_ROLLNEVER
	 * is specified.  Apparently complete external control over the log
	 * files is desired.
	 */
	if (FILE_VERSIONS(channel) == ISC_LOG_ROLLNEVER)
		return (ISC_R_SUCCESS);

	path = FILE_NAME(channel);

	/*
	 * Set greatest_version to the greatest existing version
	 * (not the maximum requested version).  This is 1 based even
	 * though the file names are 0 based, so an oldest log of log.1
	 * is a greatest_version of 2.
	 */
	greatest = greatest_version(channel);

	/*
	 * Now greatest should be set to the highest version number desired.
	 * Since the highest number is one less than FILE_VERSIONS(channel)
	 * when not doing infinite log rolling, greatest will need to be
	 * decremented when it is equal to -- or greater than --
	 * FILE_VERSIONS(channel).  When greatest is less than 
	 * FILE_VERSIONS(channel), it is already suitable for use as
	 * the maximum version number.
	 */

	if (FILE_VERSIONS(channel) == ISC_LOG_ROLLINFINITE ||
	    FILE_VERSIONS(channel) > greatest)
		;		/* Do nothing. */
	else
		/*
		 * When greatest is >= FILE_VERSIONS(channel), it needs to
		 * be reduced until it is FILE_VERSIONS(channel) - 1.
		 * Remove any excess logs on the way to that value.
		 */
		while (--greatest >= FILE_VERSIONS(channel)) {
			sprintf(current, "%s.%d", path, greatest);
			(void)remove(current);
		}

	for (i = greatest; i > 0; i /= 10)
		digits++;

	/*
	 * Ensure the name fits in the filesystem.  Note that in this will not
	 * trigger failure until there is going to be a log rolled into a name
	 * that is too long, not when the maximum possible version name would
	 * be too long.  Imagine a case where the name for logs 0-9 is exactly
	 * as long as the maximum filename, but FILE_VERSIONS is configured as
	 * 11.  log.10's name will be too long, but no error will be triggered
	 * until log.9 exists and needs to be rolled.
	 */
	if (strlen(path) + 1 + digits > FILENAME_MAX)
		return (ISC_R_INVALIDFILE);

	for (i = greatest; i > 0; i--) {
		sprintf(current, "%s.%d", path, i - 1);
		sprintf(new, "%s.%d", path, i);
		(void)rename(current, new);
	}

	if (FILE_VERSIONS(channel) != 0) {
		sprintf(new, "%s.0", path);
		(void)rename(path, new);

	} else if (FILE_VERSIONS(channel) == 0)
		(void)remove(path);

	return (ISC_R_SUCCESS);
}

static isc_result_t
isc_log_open(isc_logchannel_t *channel) {
	FILE *stream;
	struct stat statbuf;
	isc_boolean_t regular_file;
	char *path;

	REQUIRE(channel->type == ISC_LOG_TOFILE);
	REQUIRE(FILE_STREAM(channel) == NULL);

	path = FILE_NAME(channel);

	REQUIRE(path != NULL && *path != '\0');

	/*
	 * Determine type of file; only regular files will be
	 * version renamed.
	 */
	if (stat(path, &statbuf) == 0)
		regular_file = (statbuf.st_mode & S_IFREG) ?
							ISC_TRUE : ISC_FALSE;
	else if (errno == ENOENT)
		regular_file = ISC_TRUE;
	else
		return (ISC_R_INVALIDFILE);

	/*
	 * Version control.
	 */
	if (regular_file)
		if (roll_log(channel) != ISC_R_SUCCESS)
			return (ISC_R_INVALIDFILE);
	/* XXXDCL if not regular_file complain? */

	stream = fopen(path, "a");
	if (stream == NULL)
		return (ISC_R_INVALIDFILE);

	FILE_STREAM(channel) = stream;

	return (ISC_R_SUCCESS);
}

static void
isc_log_doit(isc_log_t *lctx, isc_logcategory_t *category,
	     isc_logmodule_t *module, int level, isc_boolean_t write_once,
	     const char *format, va_list args)
{
	int syslog_level;
	char time_string[64];
	char level_string[24];
	struct stat statbuf;
	struct tm *timeptr;
	time_t now;
	isc_boolean_t matched = ISC_FALSE;
	isc_logchannel_t *channel;
	isc_logchannellist_t *category_channels;
	isc_result_t result;

	REQUIRE(lctx == NULL || VALID_CONTEXT(lctx));

	/*
	 * Programs can use libraries that use this logging code without
	 * wanting to do any logging, thus the log context is allowed to
	 * be non-existent.
	 */
	if (lctx == NULL)
		return;

	REQUIRE(category != NULL && category->id < lctx->category_count);
	REQUIRE(module != NULL && module->id < lctx->module_count);
	REQUIRE(level != ISC_LOG_DYNAMIC);
	REQUIRE(format != NULL);

	time_string[0] = '\0';
	level_string[0] = '\0';
	lctx->buffer[0] = '\0';

	category_channels = lctx->categories[category->id];

	if (isc_mutex_lock(&lctx->lock) != ISC_R_SUCCESS)
		return;

	/*
	 * XXX duplicate filtering (do not write multiple times to same source
	 * via various channels)
	 */
	do {
		/*
		 * If the channel list end was reached and a match was made,
		 * everything is finished.
		 */
		if (category_channels == NULL && matched)
			break;

		if (category_channels == NULL && ! matched &&
		    category_channels != lctx->categories[0])
			/*
			 * No category/module pair was explicitly configured.
			 * Try the category named "default".
			 */
			category_channels = lctx->categories[0];

		if (category_channels == NULL && ! matched)
			/*
			 * No matching module was explicitly configured
			 * for the category named "default".  Use the internal
			 * default channel.
			 */
			category_channels = &default_channel;
 
		if (category_channels->module != NULL &&
		    category_channels->module != module) {
			category_channels = category_channels->next;
			continue;
		}

		matched = ISC_TRUE;

		channel = category_channels->channel;
		category_channels = category_channels->next;

		if (channel->level == ISC_LOG_DYNAMIC) {
			if (lctx->debug_level < level)
				continue;
		} else if (channel->level < level)
			continue;

		if ((channel->flags & ISC_LOG_PRINTTIME) &&
		    time_string[0] == '\0') {
			time(&now);

			timeptr = localtime(&now);

			/*
			 * Emulate syslog's time format.
			 * XXXDCL it would be nice if format were configurable.
			 */
			strftime(time_string, sizeof(time_string),
				 "%b %d %X ", timeptr);
		}

		if ((channel->flags & ISC_LOG_PRINTLEVEL) &&
		    level_string[0] == '\0') {
			if (level < ISC_LOG_CRITICAL)
				sprintf(level_string, "level %d: ", level);
			else if (level > ISC_LOG_DYNAMIC)
				sprintf(level_string, "%s %d: ",
					log_level_strings[0], level);
			else
				sprintf(level_string, "%s: ",
					log_level_strings[-level]);
		}

		/*
		 * Only format the message once.
		 */
		if (lctx->buffer[0] == '\0') {
			(void)vsnprintf(lctx->buffer, sizeof(lctx->buffer),
					format, args);

			/*
			 * Check for duplicates.
			 */
			if (write_once) {
				isc_logmessage_t *message, *new;
				isc_time_t oldest;
				isc_interval_t interval;

				isc_interval_set(&interval,
						 lctx->duplicate_interval, 0);

				/*
				 * 'oldest' is the age of the oldest messages
				 * which fall within the duplicate_interval
				 * range.
				 */
				if (isc_time_now(&oldest) != ISC_R_SUCCESS)
					message = NULL;
				else
					isc_time_subtract(&oldest, &interval,
							  &oldest);

				message = ISC_LIST_HEAD(lctx->messages);
				while (message != NULL) {
					if (isc_time_compare(&message->time,
							     &oldest) < 0) {
						/*
						 * This message is older
						 * than the duplicate_interval,
						 * so it should be dropped from
						 * the history.
						 *
						 * XXX Setting the interval
						 * to be longer will obviously
						 * not cause the expired 
						 * message to spring back into
						 * existence.
						 */
						new = message->next;
						isc_mem_put(lctx->mctx,
							message,
							sizeof(*message) + 1 +
							strlen(message->text));

						lctx->messages.head = new;
						if (new == NULL)
							/*
							 * Last element of the
							 * list was removed, so
							 * the tail pointer
							 * is no longer valid.
							 */
							lctx->messages.tail =
								NULL;

						message = new;
						continue;
					}

					/*
					 * This message is in the duplicate
					 * filtering interval ...
					 */
					if (strcmp(lctx->buffer, message->text)
					    == 0) {
						/*
						 * ... and it is a duplicate.
						 * Unlock the mutex and
						 * get the hell out of Dodge.
						 */
						isc_mutex_unlock(&lctx->lock);
						return;
					}

					message = message->next;
				}

				/*
				 * It wasn't in the duplicate interval,
				 * so add it to the message list.
				 */
				new = isc_mem_get(lctx->mctx,
						  sizeof(isc_logmessage_t) +
						  strlen(lctx->buffer) + 1);
				if (new != NULL) {
					/*
					 * Put the text immediately after
					 * the struct.  The strcpy is safe.
					 */
					new->text = (char *)(new + 1);
					strcpy(new->text, lctx->buffer);

					if (isc_time_now(&new->time) !=
					    ISC_R_SUCCESS)
						/*
						 * This will cause the message
						 * to immediately expire on
						 * the next call to [v]write1.
						 * XXX ok?
						 */
					       isc_time_settoepoch(&new->time);

					new->next = NULL;

					if (ISC_LIST_EMPTY(lctx->messages)) {
						lctx->messages.head = new;
						lctx->messages.tail = new;
					} else {
						lctx->messages.tail->next =
							new;
						lctx->messages.tail = new;
					}
				}
			}
		}

		switch (channel->type) {
		case ISC_LOG_TOFILE:
			if (FILE_STREAM(channel) == NULL) {
				result = isc_log_open(channel);
				if (result != ISC_R_SUCCESS)
					break;
				/*
				 * Probably something more meaningful should be
				 * done with an error.
				 */
			}
			/* FALLTHROUGH */

		case ISC_LOG_TOFILEDESC:
			fprintf(FILE_STREAM(channel), "%s%s%s%s%s%s%s\n",
				(channel->flags & ISC_LOG_PRINTTIME) ?
					time_string : "",
				(channel->flags & ISC_LOG_PRINTCATEGORY) ?
					category->name : "",
				(channel->flags & ISC_LOG_PRINTCATEGORY) ?
					": " : "",
				(channel->flags & ISC_LOG_PRINTMODULE) ?
					(module != NULL ? module->name :
					                  "no_module")
					: "",
				(channel->flags & ISC_LOG_PRINTMODULE) ?
					": " : "",
				(channel->flags & ISC_LOG_PRINTLEVEL) ?
					level_string : "",
				lctx->buffer);

			fflush(FILE_STREAM(channel));

			/*
			 * If the file now exceeds its maximum size
			 * threshold, close it and mark it ready
			 * for reopening the next time the channel is used.
			 */
			if (FILE_MAXSIZE(channel) != 0) {
				INSIST(channel->type == ISC_LOG_TOFILE);

				/* XXXDCL NT fstat/fileno */
				/* XXXDCL complain if fstat fails? */
				if (fstat(fileno(FILE_STREAM(channel)),
					  &statbuf) >= 0 &&
				    statbuf.st_size > FILE_MAXSIZE(channel)) {
					fclose(FILE_STREAM(channel));
					FILE_STREAM(channel) = NULL;
				}
			}

			break;

		case ISC_LOG_TOSYSLOG:
			if (level > 0)
				syslog_level = LOG_DEBUG;
			else if (level < ISC_LOG_CRITICAL)
				syslog_level = LOG_CRIT;
			else
				syslog_level = syslog_map[-level];

			syslog(FACILITY(channel) | syslog_level,
			       "%s%s%s%s%s%s%s",
			       (channel->flags & ISC_LOG_PRINTTIME) ?
			       		time_string : "",
			       (channel->flags & ISC_LOG_PRINTCATEGORY) ?
			       		category->name : "",
			       (channel->flags & ISC_LOG_PRINTCATEGORY) ?
			       		": " : "",
			       (channel->flags & ISC_LOG_PRINTMODULE) ?
					(module != NULL ? module->name :
					                  "no_module")
			       		: "",
			       (channel->flags & ISC_LOG_PRINTMODULE) ?
			       		": " : "",
			       (channel->flags & ISC_LOG_PRINTLEVEL) ?
			       		level_string : "",
			       lctx->buffer);
			break;

		case ISC_LOG_TONULL:
			break;

		}

	} while (1);

	isc_mutex_unlock(&lctx->lock);
}
