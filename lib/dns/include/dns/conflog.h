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
 * 	No impact.
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
typedef struct dns_c_logging_list	dns_c_logging_list_t;

/* The structure that holds the list of channel and category definitions */
struct dns_c_logging_list
{
	isc_mem_t	       	       *mem;

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
			isc_int32_t	versions;
			isc_uint32_t	size;
		} filec;
		struct			/* when ctype == dns_c_logchan_syslog*/
		{
			int		facility;
		} syslogc;
	} u;

	dns_c_log_severity_t 		severity;
	isc_int32_t			debug_level;

	isc_boolean_t			print_category;
	isc_boolean_t			print_severity;
	isc_boolean_t			print_time;

	/* Some channels are predefined e.g. default_syslog, in which case
	 * this is true
	 */
	isc_boolean_t			predefined; 
	
	ISC_LINK(dns_c_logchan_t)	next;
	dns_setbits_t			setflags;
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

isc_result_t	dns_c_logging_list_new(isc_mem_t *mem,
				       dns_c_logging_list_t **list);
isc_result_t	dns_c_logging_list_delete(dns_c_logging_list_t **list);
void		dns_c_logging_list_print(FILE *fp, int indent,
					 dns_c_logging_list_t *ll,
					 isc_boolean_t if_predef_too);
isc_result_t	dns_c_logging_list_copy(isc_mem_t *mem,
					dns_c_logging_list_t **dest,
					dns_c_logging_list_t *src);

isc_result_t	dns_c_logging_list_add_channel(dns_c_logging_list_t *list,
					       dns_c_logchan_t *newchan,
					       isc_boolean_t deepcopy);
isc_result_t	dns_c_logging_list_add_category(dns_c_logging_list_t *list,
						dns_c_logcat_t *newcat,
						isc_boolean_t *deepcopy);
isc_result_t	dns_c_logging_list_del_channel(dns_c_logging_list_t *list,
					       const char *name);
isc_result_t	dns_c_logging_list_del_category(dns_c_logging_list_t *list,
						const char *name);

isc_result_t	dns_c_logging_list_chanbyname(dns_c_logging_list_t *list,
					      const char *name,
					      dns_c_logchan_t **chan);
isc_result_t	dns_c_logging_list_catbyname(dns_c_logging_list_t *list,
					     const char *name,
					     dns_c_logcat_t **cat);
isc_result_t	dns_c_logging_list_catbytype(dns_c_logging_list_t *list,
					     dns_c_category_t cattype,
					     dns_c_logcat_t **cat);


isc_result_t	dns_c_logchan_new(isc_mem_t *mem, const char *name,
				  dns_c_logchantype_t ctype,
				  dns_c_logchan_t **newchan);
isc_result_t	dns_c_logchan_delete(dns_c_logchan_t **channel);
isc_result_t	dns_c_logchan_copy(isc_mem_t *mem, dns_c_logchan_t **dest,
				   dns_c_logchan_t *src);
void		dns_c_logchan_print(FILE *fp, int indent,
				    dns_c_logchan_t *logchan,
				    isc_boolean_t if_predef_too);


isc_result_t	dns_c_logchan_set_path(dns_c_logchan_t *channel,
				       const char *path);
isc_result_t	dns_c_logchan_set_versions(dns_c_logchan_t *channel,
					   isc_int32_t versions);
isc_result_t	dns_c_logchan_set_size(dns_c_logchan_t *channel,
				       isc_uint32_t size);
isc_result_t	dns_c_logchan_set_facility(dns_c_logchan_t *channel,
					   int facility);
isc_result_t	dns_c_logchan_set_severity(dns_c_logchan_t *channel,
					   dns_c_log_severity_t severity);
isc_result_t	dns_c_logchan_set_debug_level(dns_c_logchan_t *channel,
					      isc_int32_t level);
isc_result_t	dns_c_logchan_set_printcat(dns_c_logchan_t *channel,
					   isc_boolean_t newval);
isc_result_t	dns_c_logchan_set_printsev(dns_c_logchan_t *channel,
					   isc_boolean_t newval);
isc_result_t	dns_c_logchan_set_printtime(dns_c_logchan_t *channel,
					    isc_boolean_t newval);
isc_result_t	dns_c_logchan_set_predef(dns_c_logchan_t *channel,
					 isc_boolean_t newval);

isc_result_t	dns_c_logchan_get_path(dns_c_logchan_t *channel,
				       const char **path);
isc_result_t	dns_c_logchan_get_versions(dns_c_logchan_t *channel,
					   isc_int32_t *versions);
isc_result_t	dns_c_logchan_get_size(dns_c_logchan_t *channel,
				       isc_uint32_t *size);
isc_result_t	dns_c_logchan_get_facility(dns_c_logchan_t *channel,
					   int *facility);
isc_result_t	dns_c_logchan_get_severity(dns_c_logchan_t *channel,
					   dns_c_log_severity_t *severity);
isc_result_t	dns_c_logchan_get_debug_level(dns_c_logchan_t *channel,
					      isc_int32_t *level);
isc_result_t	dns_c_logchan_get_printcat(dns_c_logchan_t *channel,
					   isc_boolean_t *retval);
isc_result_t	dns_c_logchan_get_printsev(dns_c_logchan_t *channel,
					   isc_boolean_t *retval);
isc_result_t	dns_c_logchan_get_printtime(dns_c_logchan_t *channel,
					    isc_boolean_t *retval);
isc_result_t	dns_c_logchan_get_predef(dns_c_logchan_t *channel,
					 isc_boolean_t *retval);



/*
 * Logging category
 */
isc_result_t	dns_c_logcat_new(isc_mem_t *mem, dns_c_category_t cat,
				 dns_c_logcat_t **newlc);
isc_result_t	dns_c_logcat_delete(dns_c_logcat_t **logcat);
void		dns_c_logcat_print(FILE *fp, int indent,
				   dns_c_logcat_t *logcat,
				   isc_boolean_t if_predef_too);
isc_result_t	dns_c_logcat_copy(isc_mem_t *mem, dns_c_logcat_t **dest,
				  dns_c_logcat_t *src);
isc_result_t	dns_c_logcat_add_name(dns_c_logcat_t *logcat,
				      const char *name);
isc_result_t	dns_c_logcat_del_name(dns_c_logcat_t *logcat,
				      const char *name);
isc_result_t	dns_c_logcat_set_predef(dns_c_logcat_t *logcat,
					isc_boolean_t newval);
isc_result_t	dns_c_logcat_get_predef(dns_c_logcat_t *logcat,
					isc_boolean_t *retval);

#endif /* ISC_WHATEVER_H */
