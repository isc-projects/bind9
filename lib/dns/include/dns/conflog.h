/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#ifndef DNS_CONFIG_CONFLOG_H
#define DNS_CONFIG_CONFLOG_H 1

/*****
 ***** Module Info
 *****/

/*
 * Various ADTs for holding the values defined inside a config
 * file's "logging" statement.
 */

/*
 * MP:
 *
 *	Caller must do appropriate locking
 *	
 * Reliability:
 *
 *	No impact.
 *
 * Resources:
 *
 *	Caller supplies memory allocators
 *	
 * Security:
 *
 *	No impact.
 *
 * Standards:
 *
 *	N/A
 *	
 */

/***
 *** Imports
 ***/

#include <config.h>

#include <isc/mem.h>

#include <dns/confcommon.h>


/***
 *** Types
 ***/

typedef struct dns_c_logchan		dns_c_logchan_t;
typedef struct dns_c_logcat		dns_c_logcat_t;
typedef struct dns_c_logging_list	dns_c_logginglist_t;

/* The structure that holds the list of channel and category definitions */
struct dns_c_logging_list
{
	isc_mem_t		       *mem;

	ISC_LIST(dns_c_logchan_t)	channels;
	ISC_LIST(dns_c_logcat_t)	categories;
};


/* Definition of a logging channel */
struct dns_c_logchan
{
	isc_mem_t		       *mem;

	char			       *name;

	dns_c_logchantype_t		ctype; 
	union {
		struct
		{			/* when ctype == dns_c_logchan_file */
			char		*path;
			isc_uint32_t	versions;
			isc_uint32_t	size;
		} filec;
		struct			/* when ctype == dns_c_logchan_syslog*/
		{
			int		facility;
		} syslogc;
	} u;

	dns_c_logseverity_t		severity;
	isc_int32_t			debug_level;

	isc_boolean_t			print_category;
	isc_boolean_t			print_severity;
	isc_boolean_t			print_time;

	/* Some channels are predefined e.g. default_syslog, in which case
	 * this is true
	 */
	isc_boolean_t			predefined; 
	
	ISC_LINK(dns_c_logchan_t)	next;
	dns_c_setbits_t			setflags;
};


/* Structure for holding a category definition */
struct dns_c_logcat
{
	isc_mem_t		       *mem;

	dns_c_category_t		category;

	char			      **channel_names;
	size_t				cnames_len; /* size, in elements of 
						     channel_names */
	size_t				nextcname; /* index in
						      channel_names of next 
						      free spot. */
	
	isc_boolean_t			predefined;

	ISC_LINK(dns_c_logcat_t)	next;
};


/***
 *** Functions
 ***/

isc_result_t	dns_c_logginglist_new(isc_log_t *lctx,
				      isc_mem_t *mem,
				      dns_c_logginglist_t **list);
isc_result_t	dns_c_logginglist_delete(isc_log_t *lctx,
					 dns_c_logginglist_t **list);
void		dns_c_logginglist_print(isc_log_t *lctx,
					FILE *fp, int indent,
					dns_c_logginglist_t *ll,
					isc_boolean_t if_predef_too);
isc_result_t	dns_c_logginglist_copy(isc_log_t *lctx,
				       isc_mem_t *mem,
				       dns_c_logginglist_t **dest,
				       dns_c_logginglist_t *src);

isc_result_t	dns_c_logginglist_addchannel(isc_log_t *lctx,
					     dns_c_logginglist_t *list,
					     dns_c_logchan_t *newchan,
					     isc_boolean_t deepcopy);
isc_result_t	dns_c_logginglist_addcategory(isc_log_t *lctx,
					      dns_c_logginglist_t *list,
					      dns_c_logcat_t *newcat,
					      isc_boolean_t deepcopy);
isc_result_t	dns_c_logginglist_delchannel(isc_log_t *lctx,
					     dns_c_logginglist_t *list,
					     const char *name);
isc_result_t	dns_c_logginglist_delcategory(isc_log_t *lctx,
					      dns_c_logginglist_t *list,
					      const char *name);

isc_result_t	dns_c_logginglist_chanbyname(isc_log_t *lctx,
					     dns_c_logginglist_t *list,
					     const char *name,
					     dns_c_logchan_t **chan);
isc_result_t	dns_c_logginglist_catbyname(isc_log_t *lctx,
					    dns_c_logginglist_t *list,
					    const char *name,
					    dns_c_logcat_t **cat);
isc_result_t	dns_c_logginglist_catbytype(isc_log_t *lctx,
					    dns_c_logginglist_t *list,
					    dns_c_category_t cattype,
					    dns_c_logcat_t **cat);


isc_result_t	dns_c_logchan_new(isc_log_t *lctx,
				  isc_mem_t *mem, const char *name,
				  dns_c_logchantype_t ctype,
				  dns_c_logchan_t **newchan);
isc_result_t	dns_c_logchan_delete(isc_log_t *lctx,
				     dns_c_logchan_t **channel);
isc_result_t	dns_c_logchan_copy(isc_log_t *lctx,
				   isc_mem_t *mem, dns_c_logchan_t **dest,
				   dns_c_logchan_t *src);
void		dns_c_logchan_print(isc_log_t *lctx,
				    FILE *fp, int indent,
				    dns_c_logchan_t *logchan,
				    isc_boolean_t if_predef_too);


isc_result_t	dns_c_logchan_setpath(isc_log_t *lctx,
				      dns_c_logchan_t *channel,
				      const char *path);
isc_result_t	dns_c_logchan_setversions(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  isc_uint32_t versions);
isc_result_t	dns_c_logchan_setsize(isc_log_t *lctx,
				      dns_c_logchan_t *channel,
				      isc_uint32_t size);
isc_result_t	dns_c_logchan_setfacility(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  int facility);
isc_result_t	dns_c_logchan_setseverity(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  dns_c_logseverity_t severity);
isc_result_t	dns_c_logchan_setdebuglevel(isc_log_t *lctx,
					    dns_c_logchan_t *channel,
					    isc_int32_t level);
isc_result_t	dns_c_logchan_setprintcat(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  isc_boolean_t newval);
isc_result_t	dns_c_logchan_setprintsev(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  isc_boolean_t newval);
isc_result_t	dns_c_logchan_setprinttime(isc_log_t *lctx,
					   dns_c_logchan_t *channel,
					   isc_boolean_t newval);
isc_result_t	dns_c_logchan_setpredef(isc_log_t *lctx,
					dns_c_logchan_t *channel,
					isc_boolean_t newval);

isc_result_t	dns_c_logchan_getpath(isc_log_t *lctx,
				      dns_c_logchan_t *channel,
				      const char **path);
isc_result_t	dns_c_logchan_getversions(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  isc_uint32_t *versions);
isc_result_t	dns_c_logchan_getsize(isc_log_t *lctx,
				      dns_c_logchan_t *channel,
				      isc_uint32_t *size);
isc_result_t	dns_c_logchan_getfacility(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  int *facility);
isc_result_t	dns_c_logchan_getseverity(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  dns_c_logseverity_t *severity);
isc_result_t	dns_c_logchan_getdebuglevel(isc_log_t *lctx,
					    dns_c_logchan_t *channel,
					    isc_int32_t *level);
isc_result_t	dns_c_logchan_getprintcat(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  isc_boolean_t *retval);
isc_result_t	dns_c_logchan_getprintsev(isc_log_t *lctx,
					  dns_c_logchan_t *channel,
					  isc_boolean_t *retval);
isc_result_t	dns_c_logchan_getprinttime(isc_log_t *lctx,
					   dns_c_logchan_t *channel,
					   isc_boolean_t *retval);
isc_result_t	dns_c_logchan_getpredef(isc_log_t *lctx,
					dns_c_logchan_t *channel,
					isc_boolean_t *retval);



/*
 * Logging category
 */
isc_result_t	dns_c_logcat_new(isc_log_t *lctx,
				 isc_mem_t *mem, dns_c_category_t cat,
				 dns_c_logcat_t **newlc);
isc_result_t	dns_c_logcat_delete(isc_log_t *lctx,
				    dns_c_logcat_t **logcat);
void		dns_c_logcat_print(isc_log_t *lctx,
				   FILE *fp, int indent,
				   dns_c_logcat_t *logcat,
				   isc_boolean_t if_predef_too);
isc_result_t	dns_c_logcat_copy(isc_log_t *lctx,
				  isc_mem_t *mem, dns_c_logcat_t **dest,
				  dns_c_logcat_t *src);
isc_result_t	dns_c_logcat_addname(isc_log_t *lctx,
				     dns_c_logcat_t *logcat,
				     const char *name);
isc_result_t	dns_c_logcat_delname(isc_log_t *lctx,
				     dns_c_logcat_t *logcat,
				     const char *name);
isc_result_t	dns_c_logcat_setpredef(isc_log_t *lctx,
				       dns_c_logcat_t *logcat,
				       isc_boolean_t newval);
isc_result_t	dns_c_logcat_getpredef(isc_log_t *lctx,
				       dns_c_logcat_t *logcat,
					isc_boolean_t *retval);

#endif /* ISC_WHATEVER_H */
