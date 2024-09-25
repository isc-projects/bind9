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

/*! \file */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h> /* dev_t FreeBSD 2.1 */
#include <time.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/dir.h>
#include <isc/errno.h>
#include <isc/file.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#define LCTX_MAGIC	    ISC_MAGIC('L', 'c', 't', 'x')
#define VALID_CONTEXT(lctx) ISC_MAGIC_VALID(lctx, LCTX_MAGIC)

#define LCFG_MAGIC	   ISC_MAGIC('L', 'c', 'f', 'g')
#define VALID_CONFIG(lcfg) ISC_MAGIC_VALID(lcfg, LCFG_MAGIC)

static thread_local bool forcelog = false;

/*
 * XXXDCL make dynamic?
 */
#define LOG_BUFFER_SIZE (8 * 1024)

/*
 * Private isc_log_t data type.
 */
typedef struct isc_log isc_log_t;

/*!
 * This is the structure that holds each named channel.  A simple linked
 * list chains all of the channels together, so an individual channel is
 * found by doing strcmp()s with the names down the list.  Their should
 * be no performance penalty from this as it is expected that the number
 * of named channels will be no more than a dozen or so, and name lookups
 * from the head of the list are only done when isc_log_usechannel() is
 * called, which should also be very infrequent.
 */
typedef struct isc_logchannel isc_logchannel_t;

struct isc_logchannel {
	char *name;
	unsigned int type;
	int level;
	unsigned int flags;
	isc_logdestination_t destination;
	ISC_LINK(isc_logchannel_t) link;
};

/*!
 * The logchannellist structure associates categories and modules with
 * channels.  First the appropriate channellist is found based on the
 * category, and then each structure in the linked list is checked for
 * a matching module.  It is expected that the number of channels
 * associated with any given category will be very short, no more than
 * three or four in the more unusual cases.
 */
typedef struct isc_logchannellist isc_logchannellist_t;

struct isc_logchannellist {
	isc_logmodule_t module;
	isc_logchannel_t *channel;
	ISC_LINK(isc_logchannellist_t) link;
};

/*!
 * This structure is used to remember messages for pruning via
 * isc_log_[v]write1().
 */
typedef struct isc_logmessage isc_logmessage_t;

struct isc_logmessage {
	char *text;
	isc_time_t time;
	ISC_LINK(isc_logmessage_t) link;
};

/*!
 * The isc_logconfig structure is used to store the configurable information
 * about where messages are actually supposed to be sent -- the information
 * that could changed based on some configuration file, as opposed to the
 * the category/module specification of isc_log_[v]write[1] that is compiled
 * into a program, or the debug_level which is dynamic state information.
 */
struct isc_logconfig {
	unsigned int magic;
	isc_log_t *lctx;
	ISC_LIST(isc_logchannel_t) channels;
	ISC_LIST(isc_logchannellist_t) channellists[ISC_LOGCATEGORY_MAX];
	int_fast32_t highest_level;
	char *tag;
	bool dynamic;
};

/*!
 * This isc_log structure provides the context for the isc_log functions.
 * The log context locks itself in isc_log_doit, the internal backend to
 * isc_log_write.  The locking is necessary both to provide exclusive access
 * to the buffer into which the message is formatted and to guard against
 * competing threads trying to write to the same syslog resource.
 *
 * FIXME: We can remove the locking by using per-thread .buffer.
 */
struct isc_log {
	/* Not locked. */
	unsigned int magic;
	isc_mem_t *mctx;
	atomic_int_fast32_t debug_level;
	/* RCU-protected pointer */
	isc_logconfig_t *logconfig;
	isc_mutex_t lock;
	/* Locked by isc_log lock. */
	char buffer[LOG_BUFFER_SIZE];
	atomic_bool dynamic;
	atomic_int_fast32_t highest_level;
};

/*!
 * Used when ISC_LOG_PRINTLEVEL is enabled for a channel.
 */
static const char *log_level_strings[] = { "debug",   "info",  "notice",
					   "warning", "error", "critical" };

/*!
 * Used to convert ISC_LOG_* priorities into syslog priorities.
 * XXXDCL This will need modification for NT.
 */
static const int syslog_map[] = { LOG_DEBUG,   LOG_INFO, LOG_NOTICE,
				  LOG_WARNING, LOG_ERR,	 LOG_CRIT };

/*!
 * When adding new categories, a corresponding ISC_LOGCATEGORY_foo
 * definition needs to be added to <isc/log.h>.
 *
 * The default category is provided so that the internal default can
 * be overridden.  Since the default is always looked up as the first
 * channellist in the log context, it must come first in isc_categories[].
 */
static const char *categories_description[] = {
	/* libisc categories */
	[ISC_LOGCATEGORY_DEFAULT] = "default",
	[ISC_LOGCATEGORY_GENERAL] = "general",
	[ISC_LOGCATEGORY_SSLKEYLOG] = "sslkeylog",
	/* dns categories */
	[DNS_LOGCATEGORY_NOTIFY] = "notify",
	[DNS_LOGCATEGORY_DATABASE] = "database",
	[DNS_LOGCATEGORY_SECURITY] = "security",
	[DNS_LOGCATEGORY_DNSSEC] = "dnssec",
	[DNS_LOGCATEGORY_RESOLVER] = "resolver",
	[DNS_LOGCATEGORY_XFER_IN] = "xfer-in",
	[DNS_LOGCATEGORY_XFER_OUT] = "xfer-out",
	[DNS_LOGCATEGORY_DISPATCH] = "dispatch",
	[DNS_LOGCATEGORY_LAME_SERVERS] = "lame-servers",
	[DNS_LOGCATEGORY_EDNS_DISABLED] = "edns-disabled",
	[DNS_LOGCATEGORY_RPZ] = "rpz",
	[DNS_LOGCATEGORY_RRL] = "rate-limit",
	[DNS_LOGCATEGORY_CNAME] = "cname",
	[DNS_LOGCATEGORY_SPILL] = "spill",
	[DNS_LOGCATEGORY_DNSTAP] = "dnstap",
	[DNS_LOGCATEGORY_ZONELOAD] = "zoneload",
	[DNS_LOGCATEGORY_NSID] = "nsid",
	[DNS_LOGCATEGORY_RPZ_PASSTHRU] = "rpz-passthru",
	/* ns categories */
	[NS_LOGCATEGORY_CLIENT] = "client",
	[NS_LOGCATEGORY_NETWORK] = "network",
	[NS_LOGCATEGORY_UPDATE] = "update",
	[NS_LOGCATEGORY_QUERIES] = "queries",
	[NS_LOGCATEGORY_UPDATE_SECURITY] = "update-security",
	[NS_LOGCATEGORY_QUERY_ERRORS] = "query-errors",
	[NS_LOGCATEGORY_TAT] = "trust-anchor-telemetry",
	[NS_LOGCATEGORY_SERVE_STALE] = "serve-stale",
	[NS_LOGCATEGORY_RESPONSES] = "responses",
	/* cfg categories */
	[CFG_LOGCATEGORY_CONFIG] = "config",
	/* named categories */
	[NAMED_LOGCATEGORY_UNMATCHED] = "unmatched",
	/* delv categories */
	[DELV_LOGCATEGORY_DEFAULT] = "delv",
};

/*!
 * See above comment for categories, and apply it to modules.
 */
static const char *modules_description[] = {
	/* isc modules */
	[ISC_LOGMODULE_DEFAULT] = "no_module",
	[ISC_LOGMODULE_SOCKET] = "socket",
	[ISC_LOGMODULE_TIME] = "time",
	[ISC_LOGMODULE_INTERFACE] = "interface",
	[ISC_LOGMODULE_TIMER] = "timer",
	[ISC_LOGMODULE_FILE] = "file",
	[ISC_LOGMODULE_NETMGR] = "netmgr",
	[ISC_LOGMODULE_OTHER] = "other",
	/* dns modules */
	[DNS_LOGMODULE_DB] = "dns/db",
	[DNS_LOGMODULE_RBTDB] = "dns/rbtdb",
	[DNS_LOGMODULE_RBT] = "dns/rbt",
	[DNS_LOGMODULE_RDATA] = "dns/rdata",
	[DNS_LOGMODULE_MASTER] = "dns/master",
	[DNS_LOGMODULE_MESSAGE] = "dns/message",
	[DNS_LOGMODULE_CACHE] = "dns/cache",
	[DNS_LOGMODULE_CONFIG] = "dns/config",
	[DNS_LOGMODULE_RESOLVER] = "dns/resolver",
	[DNS_LOGMODULE_ZONE] = "dns/zone",
	[DNS_LOGMODULE_JOURNAL] = "dns/journal",
	[DNS_LOGMODULE_ADB] = "dns/adb",
	[DNS_LOGMODULE_XFER_IN] = "dns/xfrin",
	[DNS_LOGMODULE_XFER_OUT] = "dns/xfrout",
	[DNS_LOGMODULE_ACL] = "dns/acl",
	[DNS_LOGMODULE_VALIDATOR] = "dns/validator",
	[DNS_LOGMODULE_DISPATCH] = "dns/dispatch",
	[DNS_LOGMODULE_REQUEST] = "dns/request",
	[DNS_LOGMODULE_MASTERDUMP] = "dns/masterdump",
	[DNS_LOGMODULE_TSIG] = "dns/tsig",
	[DNS_LOGMODULE_TKEY] = "dns/tkey",
	[DNS_LOGMODULE_SDB] = "dns/sdb",
	[DNS_LOGMODULE_DIFF] = "dns/diff",
	[DNS_LOGMODULE_HINTS] = "dns/hints",
	[DNS_LOGMODULE_UNUSED1] = "dns/unused1",
	[DNS_LOGMODULE_DLZ] = "dns/dlz",
	[DNS_LOGMODULE_DNSSEC] = "dns/dnssec",
	[DNS_LOGMODULE_CRYPTO] = "dns/crypto",
	[DNS_LOGMODULE_PACKETS] = "dns/packets",
	[DNS_LOGMODULE_NTA] = "dns/nta",
	[DNS_LOGMODULE_DYNDB] = "dns/dyndb",
	[DNS_LOGMODULE_DNSTAP] = "dns/dnstap",
	[DNS_LOGMODULE_SSU] = "dns/ssu",
	[DNS_LOGMODULE_QP] = "dns/qp",
	/* ns modules */
	[NS_LOGMODULE_CLIENT] = "ns/client",
	[NS_LOGMODULE_QUERY] = "ns/query",
	[NS_LOGMODULE_INTERFACEMGR] = "ns/interfacemgr",
	[NS_LOGMODULE_UPDATE] = "ns/update",
	[NS_LOGMODULE_XFER_IN] = "ns/xfer-in",
	[NS_LOGMODULE_XFER_OUT] = "ns/xfer-out",
	[NS_LOGMODULE_NOTIFY] = "ns/notify",
	[NS_LOGMODULE_HOOKS] = "ns/hooks",
	/* cfg modules */
	[CFG_LOGMODULE_PARSER] = "isccfg/parser",
	/* named modules */
	[NAMED_LOGMODULE_MAIN] = "main",
	[NAMED_LOGMODULE_SERVER] = "server",
	[NAMED_LOGMODULE_CONTROL] = "control",
	/* delv modules */
	[DELV_LOGMODULE_DEFAULT] = "delv",
};

/*!
 * This essentially constant structure must be filled in at run time,
 * because its channel member is pointed to a channel that is created
 * dynamically with isc_log_createchannel.
 */
static isc_logchannellist_t default_channel;

/*!
 * libisc logs to this context.
 */
static isc_log_t *isc__lctx = NULL;

/*!
 * Forward declarations.
 */
static void
assignchannel(isc_logconfig_t *lcfg, const isc_logcategory_t category,
	      const isc_logmodule_t module, isc_logchannel_t *channel);

static void
sync_highest_level(isc_logconfig_t *lcfg);

static isc_result_t
greatest_version(isc_logfile_t *file, int versions, int *greatest);

static void
isc_log_doit(isc_logcategory_t category, isc_logmodule_t module, int level,
	     const char *format, va_list args) ISC_FORMAT_PRINTF(4, 0);

/*@{*/
/*!
 * Convenience macros.
 */

#define FACILITY(channel)	 (channel->destination.facility)
#define FILE_NAME(channel)	 (channel->destination.file.name)
#define FILE_STREAM(channel)	 (channel->destination.file.stream)
#define FILE_VERSIONS(channel)	 (channel->destination.file.versions)
#define FILE_SUFFIX(channel)	 (channel->destination.file.suffix)
#define FILE_MAXSIZE(channel)	 (channel->destination.file.maximum_size)
#define FILE_MAXREACHED(channel) (channel->destination.file.maximum_reached)

/*@}*/
/****
**** Public interfaces.
****/

void
isc_logconfig_create(isc_logconfig_t **lcfgp) {
	REQUIRE(lcfgp != NULL && *lcfgp == NULL);
	REQUIRE(VALID_CONTEXT(isc__lctx));

	int level = ISC_LOG_INFO;

	isc_logconfig_t *lcfg = isc_mem_get(isc__lctx->mctx, sizeof(*lcfg));

	*lcfg = (isc_logconfig_t){
		.magic = LCFG_MAGIC,
		.lctx = isc__lctx,
		.channels = ISC_LIST_INITIALIZER,
		.highest_level = level,
	};

	/*
	 * Create the default channels:
	 *      default_syslog, default_stderr, default_debug and null.
	 */
	isc_log_createchannel(lcfg, "default_syslog", ISC_LOG_TOSYSLOG, level,
			      ISC_LOGDESTINATION_SYSLOG(LOG_DAEMON), 0);

	isc_log_createchannel(lcfg, "default_stderr", ISC_LOG_TOFILEDESC, level,
			      ISC_LOGDESTINATION_STDERR, ISC_LOG_PRINTTIME);

	/*
	 * Set the default category's channel to default_stderr,
	 * which is at the head of the channels list because it was
	 * just created.
	 */
	default_channel.channel = ISC_LIST_HEAD(lcfg->channels);

	isc_log_createchannel(lcfg, "default_debug", ISC_LOG_TOFILEDESC,
			      ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR,
			      ISC_LOG_PRINTTIME);

	isc_log_createchannel(lcfg, "null", ISC_LOG_TONULL, ISC_LOG_DYNAMIC,
			      NULL, 0);

	*lcfgp = lcfg;
}

isc_logconfig_t *
isc_logconfig_get(void) {
	REQUIRE(VALID_CONTEXT(isc__lctx));

	return (rcu_dereference(isc__lctx->logconfig));
}

void
isc_logconfig_set(isc_logconfig_t *lcfg) {
	REQUIRE(VALID_CONTEXT(isc__lctx));
	REQUIRE(VALID_CONFIG(lcfg));
	REQUIRE(lcfg->lctx == isc__lctx);

	isc_logconfig_t *old_cfg = rcu_xchg_pointer(&isc__lctx->logconfig,
						    lcfg);
	sync_highest_level(lcfg);
	synchronize_rcu();

	if (old_cfg != NULL) {
		isc_logconfig_destroy(&old_cfg);
	}
}

void
isc_logconfig_destroy(isc_logconfig_t **lcfgp) {
	isc_logconfig_t *lcfg;
	isc_mem_t *mctx;
	isc_logchannel_t *channel;
	char *filename;

	REQUIRE(lcfgp != NULL && VALID_CONFIG(*lcfgp));

	lcfg = *lcfgp;
	*lcfgp = NULL;

	/*
	 * This function cannot be called with a logconfig that is in
	 * use by a log context.
	 */
	REQUIRE(lcfg->lctx != NULL);

	rcu_read_lock();
	REQUIRE(rcu_dereference(lcfg->lctx->logconfig) != lcfg);
	rcu_read_unlock();

	mctx = lcfg->lctx->mctx;

	while ((channel = ISC_LIST_HEAD(lcfg->channels)) != NULL) {
		ISC_LIST_UNLINK(lcfg->channels, channel, link);

		if (channel->type == ISC_LOG_TOFILE) {
			/*
			 * The filename for the channel may have ultimately
			 * started its life in user-land as a const string,
			 * but in isc_log_createchannel it gets copied
			 * into writable memory and is not longer truly const.
			 */
			filename = UNCONST(FILE_NAME(channel));
			isc_mem_free(mctx, filename);

			if (FILE_STREAM(channel) != NULL) {
				(void)fclose(FILE_STREAM(channel));
			}
		}

		isc_mem_free(mctx, channel->name);
		isc_mem_put(mctx, channel, sizeof(*channel));
	}

	for (size_t i = 0; i < ARRAY_SIZE(lcfg->channellists); i++) {
		isc_logchannellist_t *item = NULL, *next = NULL;
		ISC_LIST_FOREACH_SAFE (lcfg->channellists[i], item, link, next)
		{
			ISC_LIST_UNLINK(lcfg->channellists[i], item, link);
			isc_mem_put(mctx, item, sizeof(*item));
		}
	}

	lcfg->dynamic = false;
	if (lcfg->tag != NULL) {
		isc_mem_free(lcfg->lctx->mctx, lcfg->tag);
	}
	lcfg->tag = NULL;
	lcfg->highest_level = 0;
	lcfg->magic = 0;

	isc_mem_put(mctx, lcfg, sizeof(*lcfg));
}

isc_logcategory_t
isc_log_categorybyname(const char *name) {
	REQUIRE(VALID_CONTEXT(isc__lctx));
	REQUIRE(name != NULL);

	for (isc_logcategory_t category = 0; category < ISC_LOGCATEGORY_MAX;
	     category++)
	{
		if (strcmp(categories_description[category], name) == 0) {
			return (category);
		}
	}

	return (ISC_LOGCATEGORY_INVALID);
}

void
isc_log_createchannel(isc_logconfig_t *lcfg, const char *name,
		      unsigned int type, int level,
		      const isc_logdestination_t *destination,
		      unsigned int flags) {
	isc_logchannel_t *channel;
	isc_mem_t *mctx;
	unsigned int permitted = ISC_LOG_PRINTALL | ISC_LOG_DEBUGONLY |
				 ISC_LOG_BUFFERED | ISC_LOG_ISO8601 |
				 ISC_LOG_UTC | ISC_LOG_TZINFO;

	REQUIRE(VALID_CONFIG(lcfg));
	REQUIRE(name != NULL);
	REQUIRE(type == ISC_LOG_TOSYSLOG || type == ISC_LOG_TOFILE ||
		type == ISC_LOG_TOFILEDESC || type == ISC_LOG_TONULL);
	REQUIRE(destination != NULL || type == ISC_LOG_TONULL);
	REQUIRE(level >= ISC_LOG_CRITICAL);
	REQUIRE((flags & ~permitted) == 0);
	REQUIRE(!(flags & ISC_LOG_UTC) || !(flags & ISC_LOG_TZINFO));

	/* FIXME: find duplicate names? */

	mctx = lcfg->lctx->mctx;

	channel = isc_mem_get(mctx, sizeof(*channel));

	channel->name = isc_mem_strdup(mctx, name);

	channel->type = type;
	channel->level = level;
	channel->flags = flags;
	ISC_LINK_INIT(channel, link);

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
		FILE_NAME(channel) = isc_mem_strdup(mctx,
						    destination->file.name);
		FILE_STREAM(channel) = NULL;
		FILE_VERSIONS(channel) = destination->file.versions;
		FILE_SUFFIX(channel) = destination->file.suffix;
		FILE_MAXSIZE(channel) = destination->file.maximum_size;
		FILE_MAXREACHED(channel) = false;
		break;

	case ISC_LOG_TOFILEDESC:
		FILE_NAME(channel) = NULL;
		FILE_STREAM(channel) = destination->file.stream;
		FILE_MAXSIZE(channel) = 0;
		FILE_VERSIONS(channel) = ISC_LOG_ROLLNEVER;
		FILE_SUFFIX(channel) = isc_log_rollsuffix_increment;
		break;

	case ISC_LOG_TONULL:
		/* Nothing. */
		break;

	default:
		UNREACHABLE();
	}

	ISC_LIST_PREPEND(lcfg->channels, channel, link);

	/*
	 * If default_stderr was redefined, make the default category
	 * point to the new default_stderr.
	 */
	if (strcmp(name, "default_stderr") == 0) {
		default_channel.channel = channel;
	}
}

isc_result_t
isc_log_usechannel(isc_logconfig_t *lcfg, const char *name,
		   const isc_logcategory_t category,
		   const isc_logmodule_t module) {
	REQUIRE(VALID_CONFIG(lcfg));
	REQUIRE(name != NULL);
	REQUIRE(category >= ISC_LOGCATEGORY_DEFAULT &&
		category < ISC_LOGCATEGORY_MAX);
	REQUIRE(module >= ISC_LOGMODULE_DEFAULT && module < ISC_LOGMODULE_MAX);

	isc_logchannel_t *channel;
	for (channel = ISC_LIST_HEAD(lcfg->channels); channel != NULL;
	     channel = ISC_LIST_NEXT(channel, link))
	{
		if (strcmp(name, channel->name) == 0) {
			break;
		}
	}

	if (channel == NULL) {
		return (ISC_R_NOTFOUND);
	}

	if (category != ISC_LOGCATEGORY_DEFAULT) {
		assignchannel(lcfg, category, module, channel);
	} else {
		/*
		 * Assign to all categories.  Note that this includes
		 * the default channel.
		 */
		for (size_t i = ISC_LOGCATEGORY_DEFAULT;
		     i < ISC_LOGCATEGORY_MAX; i++)
		{
			assignchannel(lcfg, i, module, channel);
		}
	}

	/*
	 * Update the highest logging level, if the current lcfg is in use.
	 */
	rcu_read_lock();
	if (rcu_dereference(lcfg->lctx->logconfig) == lcfg) {
		sync_highest_level(lcfg);
	}
	rcu_read_unlock();

	return (ISC_R_SUCCESS);
}

void
isc_log_createandusechannel(isc_logconfig_t *lcfg, const char *name,
			    unsigned int type, int level,
			    const isc_logdestination_t *destination,
			    unsigned int flags,
			    const isc_logcategory_t category,
			    const isc_logmodule_t module) {
	isc_log_createchannel(lcfg, name, type, level, destination, flags);
	RUNTIME_CHECK(isc_log_usechannel(lcfg, name, category, module) ==
		      ISC_R_SUCCESS);
}

void
isc_log_write(isc_logcategory_t category, isc_logmodule_t module, int level,
	      const char *format, ...) {
	va_list args;

	/*
	 * Contract checking is done in isc_log_doit().
	 */

	va_start(args, format);
	isc_log_doit(category, module, level, format, args);
	va_end(args);
}

void
isc_log_vwrite(isc_logcategory_t category, isc_logmodule_t module, int level,
	       const char *format, va_list args) {
	/*
	 * Contract checking is done in isc_log_doit().
	 */
	isc_log_doit(category, module, level, format, args);
}

void
isc_log_setdebuglevel(unsigned int level) {
	REQUIRE(VALID_CONTEXT(isc__lctx));

	atomic_store_release(&isc__lctx->debug_level, level);
	/*
	 * Close ISC_LOG_DEBUGONLY channels if level is zero.
	 */
	if (level == 0) {
		rcu_read_lock();
		isc_logconfig_t *lcfg = rcu_dereference(isc__lctx->logconfig);
		if (lcfg != NULL) {
			LOCK(&isc__lctx->lock);
			for (isc_logchannel_t *channel =
				     ISC_LIST_HEAD(lcfg->channels);
			     channel != NULL;
			     channel = ISC_LIST_NEXT(channel, link))
			{
				if (channel->type == ISC_LOG_TOFILE &&
				    (channel->flags & ISC_LOG_DEBUGONLY) != 0 &&
				    FILE_STREAM(channel) != NULL)
				{
					(void)fclose(FILE_STREAM(channel));
					FILE_STREAM(channel) = NULL;
				}
			}
			UNLOCK(&isc__lctx->lock);
		}
		rcu_read_unlock();
	}
}

unsigned int
isc_log_getdebuglevel(void) {
	REQUIRE(VALID_CONTEXT(isc__lctx));

	return (atomic_load_acquire(&isc__lctx->debug_level));
}

void
isc_log_settag(isc_logconfig_t *lcfg, const char *tag) {
	REQUIRE(VALID_CONFIG(lcfg));

	if (tag != NULL && *tag != '\0') {
		if (lcfg->tag != NULL) {
			isc_mem_free(lcfg->lctx->mctx, lcfg->tag);
		}
		lcfg->tag = isc_mem_strdup(lcfg->lctx->mctx, tag);
	} else {
		if (lcfg->tag != NULL) {
			isc_mem_free(lcfg->lctx->mctx, lcfg->tag);
		}
		lcfg->tag = NULL;
	}
}

char *
isc_log_gettag(isc_logconfig_t *lcfg) {
	REQUIRE(VALID_CONFIG(lcfg));

	return (lcfg->tag);
}

/* XXXDCL NT  -- This interface will assuredly be changing. */
void
isc_log_opensyslog(const char *tag, int options, int facility) {
	(void)openlog(tag, options, facility);
}

void
isc_log_closefilelogs(void) {
	REQUIRE(VALID_CONTEXT(isc__lctx));

	rcu_read_lock();
	isc_logconfig_t *lcfg = rcu_dereference(isc__lctx->logconfig);
	if (lcfg != NULL) {
		LOCK(&isc__lctx->lock);
		for (isc_logchannel_t *channel = ISC_LIST_HEAD(lcfg->channels);
		     channel != NULL; channel = ISC_LIST_NEXT(channel, link))
		{
			if (channel->type == ISC_LOG_TOFILE &&
			    FILE_STREAM(channel) != NULL)
			{
				(void)fclose(FILE_STREAM(channel));
				FILE_STREAM(channel) = NULL;
			}
		}
		UNLOCK(&isc__lctx->lock);
	}
	rcu_read_unlock();
}

/****
**** Internal functions
****/

static void
assignchannel(isc_logconfig_t *lcfg, const isc_logcategory_t category,
	      const isc_logmodule_t module, isc_logchannel_t *channel) {
	REQUIRE(VALID_CONFIG(lcfg));
	REQUIRE(channel != NULL);

	isc_log_t *lctx = lcfg->lctx;

	REQUIRE(category >= ISC_LOGCATEGORY_DEFAULT &&
		category < ISC_LOGCATEGORY_MAX);
	REQUIRE(module >= ISC_LOGMODULE_DEFAULT && module < ISC_LOGMODULE_MAX);

	isc_logchannellist_t *new_item = isc_mem_get(lctx->mctx,
						     sizeof(*new_item));

	new_item->channel = channel;
	new_item->module = module;
	ISC_LIST_INITANDPREPEND(lcfg->channellists[category], new_item, link);

	/*
	 * Remember the highest logging level set by any channel in the
	 * logging config, so isc_log_doit() can quickly return if the
	 * message is too high to be logged by any channel.
	 */
	if (channel->type != ISC_LOG_TONULL) {
		if (lcfg->highest_level < channel->level) {
			lcfg->highest_level = channel->level;
		}
		if (channel->level == ISC_LOG_DYNAMIC) {
			lcfg->dynamic = true;
		}
	}
}

static void
sync_highest_level(isc_logconfig_t *lcfg) {
	atomic_store(&isc__lctx->highest_level, lcfg->highest_level);
	atomic_store(&isc__lctx->dynamic, lcfg->dynamic);
}

static isc_result_t
greatest_version(isc_logfile_t *file, int versions, int *greatestp) {
	char *digit_end;
	char dirbuf[PATH_MAX + 1];
	const char *bname;
	const char *dirname = ".";
	int version, greatest = -1;
	isc_dir_t dir;
	isc_result_t result;
	size_t bnamelen;

	bname = strrchr(file->name, '/');
	if (bname != NULL) {
		/*
		 * Copy the complete file name to dirbuf.
		 */
		size_t len = strlcpy(dirbuf, file->name, sizeof(dirbuf));
		if (len >= sizeof(dirbuf)) {
			result = ISC_R_NOSPACE;
			syslog(LOG_ERR, "unable to remove log files: %s",
			       isc_result_totext(result));
			return (result);
		}

		/*
		 * Truncate after trailing '/' so the code works for
		 * files in the root directory.
		 */
		bname++;
		dirbuf[bname - file->name] = '\0';
		dirname = dirbuf;
	} else {
		bname = file->name;
	}
	bnamelen = strlen(bname);

	isc_dir_init(&dir);
	result = isc_dir_open(&dir, dirname);

	/*
	 * Return if the directory open failed.
	 */
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	while (isc_dir_read(&dir) == ISC_R_SUCCESS) {
		if (dir.entry.length > bnamelen &&
		    strncmp(dir.entry.name, bname, bnamelen) == 0 &&
		    dir.entry.name[bnamelen] == '.')
		{
			version = strtol(&dir.entry.name[bnamelen + 1],
					 &digit_end, 10);
			/*
			 * Remove any backup files that exceed versions.
			 */
			if (*digit_end == '\0' && version >= versions) {
				int n = dirfd(dir.handle);
				if (n >= 0) {
					n = unlinkat(n, dir.entry.name, 0);
				}
				if (n < 0) {
					result = isc_errno_toresult(errno);
					if (result != ISC_R_SUCCESS &&
					    result != ISC_R_FILENOTFOUND)
					{
						syslog(LOG_ERR,
						       "unable to remove log "
						       "file '%s%s': %s",
						       bname == file->name
							       ? ""
							       : dirname,
						       dir.entry.name,
						       isc_result_totext(
							       result));
					}
				}
			} else if (*digit_end == '\0' && version > greatest) {
				greatest = version;
			}
		}
	}
	isc_dir_close(&dir);

	*greatestp = greatest;
	return (ISC_R_SUCCESS);
}

static void
insert_sort(int64_t to_keep[], int64_t versions, int64_t version) {
	int i = 0;
	while (i < versions && version < to_keep[i]) {
		i++;
	}
	if (i == versions) {
		return;
	}
	if (i < versions - 1) {
		memmove(&to_keep[i + 1], &to_keep[i],
			sizeof(to_keep[0]) * (versions - i - 1));
	}
	to_keep[i] = version;
}

static int64_t
last_to_keep(int64_t versions, isc_dir_t *dirp, const char *bname,
	     size_t bnamelen) {
	int64_t to_keep[ISC_LOG_MAX_VERSIONS] = { 0 };
	int64_t version = 0;

	if (versions <= 0) {
		return (INT64_MAX);
	}

	if (versions > ISC_LOG_MAX_VERSIONS) {
		versions = ISC_LOG_MAX_VERSIONS;
	}
	/*
	 * First we fill 'to_keep' structure using insertion sort
	 */
	memset(to_keep, 0, sizeof(to_keep));
	while (isc_dir_read(dirp) == ISC_R_SUCCESS) {
		char *digit_end = NULL;
		char *ename = NULL;

		if (dirp->entry.length <= bnamelen ||
		    strncmp(dirp->entry.name, bname, bnamelen) != 0 ||
		    dirp->entry.name[bnamelen] != '.')
		{
			continue;
		}

		ename = &dirp->entry.name[bnamelen + 1];
		version = strtoull(ename, &digit_end, 10);
		if (*digit_end == '\0') {
			insert_sort(to_keep, versions, version);
		}
	}

	isc_dir_reset(dirp);

	/*
	 * to_keep[versions - 1] is the last one we want to keep
	 */
	return (to_keep[versions - 1]);
}

static isc_result_t
remove_old_tsversions(isc_logfile_t *file, int versions) {
	char *digit_end;
	char dirbuf[PATH_MAX + 1];
	const char *bname;
	const char *dirname = ".";
	int64_t version, last = INT64_MAX;
	isc_dir_t dir;
	isc_result_t result;
	size_t bnamelen;

	bname = strrchr(file->name, '/');
	if (bname != NULL) {
		/*
		 * Copy the complete file name to dirbuf.
		 */
		size_t len = strlcpy(dirbuf, file->name, sizeof(dirbuf));
		if (len >= sizeof(dirbuf)) {
			result = ISC_R_NOSPACE;
			syslog(LOG_ERR, "unable to remove log files: %s",
			       isc_result_totext(result));
			return (result);
		}

		/*
		 * Truncate after trailing '/' so the code works for
		 * files in the root directory.
		 */
		bname++;
		dirbuf[bname - file->name] = '\0';
		dirname = dirbuf;
	} else {
		bname = file->name;
	}
	bnamelen = strlen(bname);

	isc_dir_init(&dir);
	result = isc_dir_open(&dir, dirname);

	/*
	 * Return if the directory open failed.
	 */
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	last = last_to_keep(versions, &dir, bname, bnamelen);

	while (isc_dir_read(&dir) == ISC_R_SUCCESS) {
		if (dir.entry.length > bnamelen &&
		    strncmp(dir.entry.name, bname, bnamelen) == 0 &&
		    dir.entry.name[bnamelen] == '.')
		{
			version = strtoull(&dir.entry.name[bnamelen + 1],
					   &digit_end, 10);
			/*
			 * Remove any backup files that exceed versions.
			 */
			if (*digit_end == '\0' && version < last) {
				int n = dirfd(dir.handle);
				if (n >= 0) {
					n = unlinkat(n, dir.entry.name, 0);
				}
				if (n < 0) {
					result = isc_errno_toresult(errno);
					if (result != ISC_R_SUCCESS &&
					    result != ISC_R_FILENOTFOUND)
					{
						syslog(LOG_ERR,
						       "unable to remove log "
						       "file '%s%s': %s",
						       bname == file->name
							       ? ""
							       : dirname,
						       dir.entry.name,
						       isc_result_totext(
							       result));
					}
				}
			}
		}
	}
	isc_dir_close(&dir);
	return (ISC_R_SUCCESS);
}

static isc_result_t
roll_increment(isc_logfile_t *file) {
	int i, n, greatest;
	char current[PATH_MAX + 1];
	char newpath[PATH_MAX + 1];
	const char *path;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(file != NULL);
	REQUIRE(file->versions != 0);

	path = file->name;

	if (file->versions == ISC_LOG_ROLLINFINITE) {
		/*
		 * Find the first missing entry in the log file sequence.
		 */
		for (greatest = 0; greatest < INT_MAX; greatest++) {
			n = snprintf(current, sizeof(current), "%s.%u", path,
				     (unsigned int)greatest);
			if (n >= (int)sizeof(current) || n < 0 ||
			    !isc_file_exists(current))
			{
				break;
			}
		}
	} else {
		/*
		 * Get the largest existing version and remove any
		 * version greater than the permitted version.
		 */
		result = greatest_version(file, file->versions, &greatest);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}

		/*
		 * Increment if greatest is not the actual maximum value.
		 */
		if (greatest < file->versions - 1) {
			greatest++;
		}
	}

	for (i = greatest; i > 0; i--) {
		result = ISC_R_SUCCESS;
		n = snprintf(current, sizeof(current), "%s.%u", path,
			     (unsigned int)(i - 1));
		if (n >= (int)sizeof(current) || n < 0) {
			result = ISC_R_NOSPACE;
		}
		if (result == ISC_R_SUCCESS) {
			n = snprintf(newpath, sizeof(newpath), "%s.%u", path,
				     (unsigned int)i);
			if (n >= (int)sizeof(newpath) || n < 0) {
				result = ISC_R_NOSPACE;
			}
		}
		if (result == ISC_R_SUCCESS) {
			result = isc_file_rename(current, newpath);
		}
		if (result != ISC_R_SUCCESS && result != ISC_R_FILENOTFOUND) {
			syslog(LOG_ERR,
			       "unable to rename log file '%s.%u' to "
			       "'%s.%u': %s",
			       path, i - 1, path, i, isc_result_totext(result));
		}
	}

	n = snprintf(newpath, sizeof(newpath), "%s.0", path);
	if (n >= (int)sizeof(newpath) || n < 0) {
		result = ISC_R_NOSPACE;
	} else {
		result = isc_file_rename(path, newpath);
	}
	if (result != ISC_R_SUCCESS && result != ISC_R_FILENOTFOUND) {
		syslog(LOG_ERR, "unable to rename log file '%s' to '%s.0': %s",
		       path, path, isc_result_totext(result));
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
roll_timestamp(isc_logfile_t *file) {
	int n;
	char newts[PATH_MAX + 1];
	char newpath[PATH_MAX + 1];
	const char *path;
	isc_time_t now;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(file != NULL);
	REQUIRE(file->versions != 0);

	path = file->name;

	/*
	 * First find all the logfiles and remove the oldest ones
	 * Save one fewer than file->versions because we'll be renaming
	 * the existing file to a timestamped version after this.
	 */
	if (file->versions != ISC_LOG_ROLLINFINITE) {
		remove_old_tsversions(file, file->versions - 1);
	}

	/* Then just rename the current logfile */
	now = isc_time_now();
	isc_time_formatshorttimestamp(&now, newts, PATH_MAX + 1);
	n = snprintf(newpath, sizeof(newpath), "%s.%s", path, newts);
	if (n >= (int)sizeof(newpath) || n < 0) {
		result = ISC_R_NOSPACE;
	} else {
		result = isc_file_rename(path, newpath);
	}
	if (result != ISC_R_SUCCESS && result != ISC_R_FILENOTFOUND) {
		syslog(LOG_ERR, "unable to rename log file '%s' to '%s.0': %s",
		       path, path, isc_result_totext(result));
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_logfile_roll(isc_logfile_t *file) {
	isc_result_t result;

	REQUIRE(file != NULL);

	/*
	 * Do nothing (not even excess version trimming) if ISC_LOG_ROLLNEVER
	 * is specified.  Apparently complete external control over the log
	 * files is desired.
	 */
	if (file->versions == ISC_LOG_ROLLNEVER) {
		return (ISC_R_SUCCESS);
	} else if (file->versions == 0) {
		result = isc_file_remove(file->name);
		if (result != ISC_R_SUCCESS && result != ISC_R_FILENOTFOUND) {
			syslog(LOG_ERR, "unable to remove log file '%s': %s",
			       file->name, isc_result_totext(result));
		}
		return (ISC_R_SUCCESS);
	}

	switch (file->suffix) {
	case isc_log_rollsuffix_increment:
		return (roll_increment(file));
	case isc_log_rollsuffix_timestamp:
		return (roll_timestamp(file));
	default:
		return (ISC_R_UNEXPECTED);
	}
}

static isc_result_t
isc_log_open(isc_logchannel_t *channel) {
	struct stat statbuf;
	bool regular_file;
	bool roll = false;
	isc_result_t result = ISC_R_SUCCESS;
	const char *path;

	REQUIRE(channel->type == ISC_LOG_TOFILE);
	REQUIRE(FILE_STREAM(channel) == NULL);

	path = FILE_NAME(channel);

	REQUIRE(path != NULL && *path != '\0');

	/*
	 * Determine type of file; only regular files will be
	 * version renamed, and only if the base file exists
	 * and either has no size limit or has reached its size limit.
	 */
	if (stat(path, &statbuf) == 0) {
		regular_file = S_ISREG(statbuf.st_mode) ? true : false;
		/* XXXDCL if not regular_file complain? */
		if ((FILE_MAXSIZE(channel) == 0 &&
		     FILE_VERSIONS(channel) != ISC_LOG_ROLLNEVER) ||
		    (FILE_MAXSIZE(channel) > 0 &&
		     statbuf.st_size >= FILE_MAXSIZE(channel)))
		{
			roll = regular_file;
		}
	} else if (errno == ENOENT) {
		regular_file = true;
		POST(regular_file);
	} else {
		result = ISC_R_INVALIDFILE;
	}

	/*
	 * Version control.
	 */
	if (result == ISC_R_SUCCESS && roll) {
		if (FILE_VERSIONS(channel) == ISC_LOG_ROLLNEVER) {
			return (ISC_R_MAXSIZE);
		}
		result = isc_logfile_roll(&channel->destination.file);
		if (result != ISC_R_SUCCESS) {
			if ((channel->flags & ISC_LOG_OPENERR) == 0) {
				syslog(LOG_ERR,
				       "isc_log_open: isc_logfile_roll '%s' "
				       "failed: %s",
				       FILE_NAME(channel),
				       isc_result_totext(result));
				channel->flags |= ISC_LOG_OPENERR;
			}
			return (result);
		}
	}

	result = isc_stdio_open(path, "a", &FILE_STREAM(channel));

	return (result);
}

ISC_NO_SANITIZE_THREAD bool
isc_log_wouldlog(int level) {
	/*
	 * Try to avoid locking the mutex for messages which can't
	 * possibly be logged to any channels -- primarily debugging
	 * messages that the debug level is not high enough to print.
	 *
	 * If the level is (mathematically) less than or equal to the
	 * highest_level, or if there is a dynamic channel and the level is
	 * less than or equal to the debug level, the main loop must be
	 * entered to see if the message should really be output.
	 */
	if (isc__lctx == NULL) {
		return (false);
	}
	if (forcelog) {
		return (true);
	}

	int highest_level = atomic_load_acquire(&isc__lctx->highest_level);
	if (level <= highest_level) {
		return (true);
	}
	if (atomic_load_acquire(&isc__lctx->dynamic)) {
		int debug_level = atomic_load_acquire(&isc__lctx->debug_level);
		if (level <= debug_level) {
			return (true);
		}
	}

	return (false);
}

static void
isc_log_doit(isc_logcategory_t category, isc_logmodule_t module, int level,
	     const char *format, va_list args) {
	int syslog_level;
	const char *time_string;
	char local_time[64] = { 0 };
	char iso8601z_string[64] = { 0 };
	char iso8601l_string[64] = { 0 };
	char iso8601tz_string[64] = { 0 };
	char level_string[24] = { 0 };
	struct stat statbuf;
	bool matched = false;
	bool printtime, iso8601, utc, tzinfo, printtag, printcolon;
	bool printcategory, printmodule, printlevel, buffered;
	isc_logchannel_t *channel;
	isc_logchannellist_t *category_channels;
	int_fast32_t dlevel;
	isc_result_t result;

	REQUIRE(isc__lctx == NULL || VALID_CONTEXT(isc__lctx));
	REQUIRE(category > ISC_LOGCATEGORY_DEFAULT &&
		category < ISC_LOGCATEGORY_MAX);
	REQUIRE(module > ISC_LOGMODULE_DEFAULT && module < ISC_LOGMODULE_MAX);
	REQUIRE(level != ISC_LOG_DYNAMIC);
	REQUIRE(format != NULL);

	if (!isc_log_wouldlog(level)) {
		return;
	}

	rcu_read_lock();
	LOCK(&isc__lctx->lock);

	isc__lctx->buffer[0] = '\0';

	isc_logconfig_t *lcfg = rcu_dereference(isc__lctx->logconfig);
	if (lcfg == NULL) {
		goto unlock;
	}

	category_channels = ISC_LIST_HEAD(lcfg->channellists[category]);

	do {
		/*
		 * If the channel list end was reached and a match was
		 * made, everything is finished.
		 */
		if (category_channels == NULL && matched) {
			break;
		}

		if (category_channels == NULL && !matched &&
		    category_channels != ISC_LIST_HEAD(lcfg->channellists[0]))
		{
			/*
			 * No category/module pair was explicitly
			 * configured. Try the category named "default".
			 */
			category_channels =
				ISC_LIST_HEAD(lcfg->channellists[0]);
		}

		if (category_channels == NULL && !matched) {
			/*
			 * No matching module was explicitly configured
			 * for the category named "default".  Use the
			 * internal default channel.
			 */
			category_channels = &default_channel;
		}

		if (category_channels->module != ISC_LOGMODULE_DEFAULT &&
		    category_channels->module != module)
		{
			category_channels = ISC_LIST_NEXT(category_channels,
							  link);
			continue;
		}

		matched = true;

		channel = category_channels->channel;
		category_channels = ISC_LIST_NEXT(category_channels, link);

		if (!forcelog) {
			dlevel = atomic_load_acquire(&isc__lctx->debug_level);
			if (((channel->flags & ISC_LOG_DEBUGONLY) != 0) &&
			    dlevel == 0)
			{
				continue;
			}

			if (channel->level == ISC_LOG_DYNAMIC) {
				if (dlevel < level) {
					continue;
				}
			} else if (channel->level < level) {
				continue;
			}
		}

		if ((channel->flags & ISC_LOG_PRINTTIME) != 0 &&
		    local_time[0] == '\0')
		{
			isc_time_t isctime;

			isctime = isc_time_now();

			isc_time_formattimestamp(&isctime, local_time,
						 sizeof(local_time));
			isc_time_formatISO8601ms(&isctime, iso8601z_string,
						 sizeof(iso8601z_string));
			isc_time_formatISO8601Lms(&isctime, iso8601l_string,
						  sizeof(iso8601l_string));
			isc_time_formatISO8601TZms(&isctime, iso8601tz_string,
						   sizeof(iso8601tz_string));
		}

		if ((channel->flags & ISC_LOG_PRINTLEVEL) != 0 &&
		    level_string[0] == '\0')
		{
			if (level < ISC_LOG_CRITICAL) {
				snprintf(level_string, sizeof(level_string),
					 "level %d: ", level);
			} else if (level > ISC_LOG_DYNAMIC) {
				snprintf(level_string, sizeof(level_string),
					 "%s %d: ", log_level_strings[0],
					 level);
			} else {
				snprintf(level_string, sizeof(level_string),
					 "%s: ", log_level_strings[-level]);
			}
		}

		/*
		 * Only format the message once.
		 */
		if (isc__lctx->buffer[0] == '\0') {
			(void)vsnprintf(isc__lctx->buffer,
					sizeof(isc__lctx->buffer), format,
					args);
		}

		utc = ((channel->flags & ISC_LOG_UTC) != 0);
		tzinfo = ((channel->flags & ISC_LOG_TZINFO) != 0);
		iso8601 = ((channel->flags & ISC_LOG_ISO8601) != 0);
		printtime = ((channel->flags & ISC_LOG_PRINTTIME) != 0);
		printtag = ((channel->flags &
			     (ISC_LOG_PRINTTAG | ISC_LOG_PRINTPREFIX)) != 0 &&
			    lcfg->tag != NULL);
		printcolon = ((channel->flags & ISC_LOG_PRINTTAG) != 0 &&
			      lcfg->tag != NULL);
		printcategory = ((channel->flags & ISC_LOG_PRINTCATEGORY) != 0);
		printmodule = ((channel->flags & ISC_LOG_PRINTMODULE) != 0);
		printlevel = ((channel->flags & ISC_LOG_PRINTLEVEL) != 0);
		buffered = ((channel->flags & ISC_LOG_BUFFERED) != 0);

		if (printtime) {
			if (iso8601) {
				if (utc) {
					time_string = iso8601z_string;
				} else if (tzinfo) {
					time_string = iso8601tz_string;
				} else {
					time_string = iso8601l_string;
				}
			} else {
				time_string = local_time;
			}
		} else {
			time_string = "";
		}

		switch (channel->type) {
		case ISC_LOG_TOFILE:
			if (FILE_MAXREACHED(channel)) {
				/*
				 * If the file can be rolled, OR
				 * If the file no longer exists, OR
				 * If the file is less than the maximum
				 * size, (such as if it had been renamed
				 * and a new one touched, or it was
				 * truncated in place)
				 * ... then close it to trigger
				 * reopening.
				 */
				if (FILE_VERSIONS(channel) !=
					    ISC_LOG_ROLLNEVER ||
				    (stat(FILE_NAME(channel), &statbuf) != 0 &&
				     errno == ENOENT) ||
				    statbuf.st_size < FILE_MAXSIZE(channel))
				{
					if (FILE_STREAM(channel) != NULL) {
						(void)fclose(
							FILE_STREAM(channel));
						FILE_STREAM(channel) = NULL;
					}
					FILE_MAXREACHED(channel) = false;
				} else {
					/*
					 * Eh, skip it.
					 */
					break;
				}
			}

			if (FILE_STREAM(channel) == NULL) {
				result = isc_log_open(channel);
				if (result != ISC_R_SUCCESS &&
				    result != ISC_R_MAXSIZE &&
				    (channel->flags & ISC_LOG_OPENERR) == 0)
				{
					syslog(LOG_ERR,
					       "isc_log_open '%s' "
					       "failed: %s",
					       FILE_NAME(channel),
					       isc_result_totext(result));
					channel->flags |= ISC_LOG_OPENERR;
				}
				if (result != ISC_R_SUCCESS) {
					break;
				}
				channel->flags &= ~ISC_LOG_OPENERR;
			}
			FALLTHROUGH;

		case ISC_LOG_TOFILEDESC:
			fprintf(FILE_STREAM(channel), "%s%s%s%s%s%s%s%s%s%s\n",
				printtime ? time_string : "",
				printtime ? " " : "", printtag ? lcfg->tag : "",
				printcolon ? ": " : "",
				printcategory ? categories_description[category]
					      : "",
				printcategory ? ": " : "",
				printmodule ? modules_description[module] : "",
				printmodule ? ": " : "",
				printlevel ? level_string : "",
				isc__lctx->buffer);

			if (!buffered) {
				fflush(FILE_STREAM(channel));
			}

			/*
			 * If the file now exceeds its maximum size
			 * threshold, note it so that it will not be
			 * logged to any more.
			 */
			if (FILE_MAXSIZE(channel) > 0) {
				INSIST(channel->type == ISC_LOG_TOFILE);

				/* XXXDCL NT fstat/fileno */
				/* XXXDCL complain if fstat fails? */
				if (fstat(fileno(FILE_STREAM(channel)),
					  &statbuf) >= 0 &&
				    statbuf.st_size > FILE_MAXSIZE(channel))
				{
					FILE_MAXREACHED(channel) = true;
				}
			}

			break;

		case ISC_LOG_TOSYSLOG:
			if (level > 0) {
				syslog_level = LOG_DEBUG;
			} else if (level < ISC_LOG_CRITICAL) {
				syslog_level = LOG_CRIT;
			} else {
				syslog_level = syslog_map[-level];
			}

			(void)syslog(
				FACILITY(channel) | syslog_level,
				"%s%s%s%s%s%s%s%s%s%s",
				printtime ? time_string : "",
				printtime ? " " : "", printtag ? lcfg->tag : "",
				printcolon ? ": " : "",
				printcategory ? categories_description[category]
					      : "",
				printcategory ? ": " : "",
				printmodule ? modules_description[module] : "",
				printmodule ? ": " : "",
				printlevel ? level_string : "",
				isc__lctx->buffer);
			break;

		case ISC_LOG_TONULL:
			break;
		}
	} while (1);

unlock:
	UNLOCK(&isc__lctx->lock);
	rcu_read_unlock();
}

void
isc_log_setforcelog(bool v) {
	forcelog = v;
}

void
isc__log_initialize(void) {
	REQUIRE(isc__lctx == NULL);

	isc_mem_t *mctx = NULL;

	isc_mem_create(&mctx);

	isc__lctx = isc_mem_get(mctx, sizeof(*isc__lctx));
	*isc__lctx = (isc_log_t){
		.magic = LCTX_MAGIC, .mctx = mctx, /* implicit attach */
	};

	isc_mutex_init(&isc__lctx->lock);

	/* Create default logging configuration */
	isc_logconfig_t *lcfg = NULL;
	isc_logconfig_create(&lcfg);

	atomic_init(&isc__lctx->highest_level, lcfg->highest_level);
	atomic_init(&isc__lctx->dynamic, lcfg->dynamic);

	isc__lctx->logconfig = lcfg;
}

void
isc__log_shutdown(void) {
	REQUIRE(VALID_CONTEXT(isc__lctx));

	isc_mem_t *mctx = isc__lctx->mctx;

	/* Stop the logging as a first thing */
	atomic_store_release(&isc__lctx->debug_level, 0);
	atomic_store_release(&isc__lctx->highest_level, 0);
	atomic_store_release(&isc__lctx->dynamic, false);

	if (isc__lctx->logconfig != NULL) {
		isc_logconfig_destroy(&isc__lctx->logconfig);
	}

	isc_mutex_destroy(&isc__lctx->lock);

	isc_mem_putanddetach(&mctx, isc__lctx, sizeof(*isc__lctx));
}
