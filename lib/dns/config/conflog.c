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

#include <config.h>

#include <string.h>

#include <isc/assertions.h>
#include <isc/magic.h>

#include <dns/conflog.h>
#include <dns/confcommon.h>
#include <dns/log.h>


#include "confpvt.h"


#define UNLIM_VERSIONS (-1)		/* XXX check this is right? */

/*
 * Bit positions in the dns_c_logchan_t structure setflags field.
 */
#define CHAN_VERSIONS_BIT		0
#define CHAN_SIZE_BIT			1
#define CHAN_SEVERITY_BIT		2
#define CHAN_DEBUG_LEVEL_BIT		3
#define CHAN_PCAT_BIT			4
#define CHAN_PSEV_BIT			5
#define CHAN_PTIME_BIT			6
#define CHAN_FACILITY_BIT		7



static void		print_log_facility(FILE *fp,
					   int value);
static void		print_log_severity(FILE *fp,
					   dns_c_logseverity_t severity);
static isc_boolean_t	logginglist_empty(dns_c_logginglist_t *ll);



isc_result_t
dns_c_logginglist_new(isc_mem_t *mem,
		      dns_c_logginglist_t **list)
{
	dns_c_logginglist_t *newl;

	REQUIRE(list != NULL);

	newl = isc_mem_get(mem, sizeof *newl);
	if (newl == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newl->magic = DNS_C_LOGLIST_MAGIC;
	newl->mem = mem;
	ISC_LIST_INIT(newl->channels);
	ISC_LIST_INIT(newl->categories);

	*list = newl;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logginglist_delete(dns_c_logginglist_t **list)
{
	dns_c_logginglist_t *l;
	dns_c_logchan_t *chan, *tmpchan;
	dns_c_logcat_t *cat, *tmpcat;
	isc_result_t res;

	REQUIRE(list != NULL);
	REQUIRE(DNS_C_LOGLIST_VALID(*list));
	
	l = *list;

	chan = ISC_LIST_HEAD(l->channels);
	while (chan != NULL) {
		tmpchan = ISC_LIST_NEXT(chan, next);
		ISC_LIST_UNLINK(l->channels, chan, next);
		res = dns_c_logchan_delete(&chan);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}

		chan = tmpchan;
	}

	cat = ISC_LIST_HEAD(l->categories);
	while (cat != NULL) {
		tmpcat = ISC_LIST_NEXT(cat, next);
		ISC_LIST_UNLINK(l->categories, cat, next);
		res = dns_c_logcat_delete(&cat);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}

		cat = tmpcat;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logginglist_copy(isc_mem_t *mem,
		       dns_c_logginglist_t **dest,
		       dns_c_logginglist_t *src)
{
	dns_c_logginglist_t *newl;
	dns_c_logchan_t *logchan, *tmplogchan;
	dns_c_logcat_t *logcat, *tmplogcat;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_LOGLIST_VALID(src));

	res = dns_c_logginglist_new(mem, &newl);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	logchan = ISC_LIST_HEAD(src->channels);
	while (logchan != NULL) {
		res = dns_c_logchan_copy(mem, &tmplogchan, logchan);
		if (res != ISC_R_SUCCESS) {
			dns_c_logginglist_delete(&newl);
			return (res);
		}

		ISC_LIST_APPEND(newl->channels, tmplogchan, next);
		logchan = ISC_LIST_NEXT(logchan, next);
	}


	logcat = ISC_LIST_HEAD(src->categories);
	while (logcat != NULL) {
		res = dns_c_logcat_copy(mem, &tmplogcat, logcat);
		if (res != ISC_R_SUCCESS) {
			dns_c_logginglist_delete(&newl);
			return (res);
		}

		ISC_LIST_APPEND(newl->categories, tmplogcat, next);
		logcat = ISC_LIST_NEXT(logcat, next);
	}

	return (ISC_R_SUCCESS);
}


static isc_boolean_t
logginglist_empty(dns_c_logginglist_t *ll)
{
	dns_c_logchan_t *logchan;
	dns_c_logcat_t *logcat;

	REQUIRE(DNS_C_LOGLIST_VALID(ll));

	logchan = ISC_LIST_HEAD(ll->channels);
	while (logchan != NULL) {
		if (!logchan->predefined) {
			return ISC_FALSE;
		}
		
		logchan = ISC_LIST_NEXT(logchan, next);
	}
	
	logcat = ISC_LIST_HEAD(ll->categories);
	while (logcat != NULL) {
		if (!logcat->predefined) {
			return ISC_FALSE;
		}
		logcat = ISC_LIST_NEXT(logcat, next);
	}

	return ISC_TRUE;
}

	
void
dns_c_logginglist_print(FILE *fp, int indent, dns_c_logginglist_t *ll,
			isc_boolean_t if_predef_too)
{
	dns_c_logchan_t *logchan;
	dns_c_logcat_t *logcat;

	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_LOGLIST_VALID(ll));

	if (logginglist_empty(ll)) {
		return;
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "logging {\n");
	
	logchan = ISC_LIST_HEAD(ll->channels);
	while (logchan != NULL) {
		dns_c_logchan_print(fp, indent + 1, logchan,
				    if_predef_too);
		logchan = ISC_LIST_NEXT(logchan, next);
	}
	
	logcat = ISC_LIST_HEAD(ll->categories);
	while (logcat != NULL) {
		dns_c_logcat_print(fp, indent + 1, logcat,
				   if_predef_too);
		logcat = ISC_LIST_NEXT(logcat, next);
	}
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_logginglist_addchannel(dns_c_logginglist_t *list,
			     dns_c_logchan_t *newchan,
			     isc_boolean_t deepcopy)
{
	dns_c_logchan_t *newc, *tmpchan;
	isc_result_t res;
	isc_boolean_t existed = ISC_FALSE;
	isc_boolean_t predefined = ISC_FALSE;

	REQUIRE(DNS_C_LOGLIST_VALID(list));
	REQUIRE(DNS_C_LOGCHAN_VALID(newchan));

	if (deepcopy) {
		res = dns_c_logchan_copy(list->mem, &newc, newchan);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		newc = newchan;
	}
		
	tmpchan = ISC_LIST_HEAD(list->channels);
	while (tmpchan != NULL) {
		if (strcmp(newchan->name, tmpchan->name) == 0) {
			existed = ISC_TRUE;
			predefined = tmpchan->predefined;

			ISC_LIST_UNLINK(list->channels, tmpchan, next);
			res = dns_c_logchan_delete(&tmpchan);
			if (res != ISC_R_SUCCESS) {
				if (deepcopy) {
					dns_c_logchan_delete(&newc);
				}
				return (res);
			}
			break;
		}

		tmpchan = ISC_LIST_NEXT(tmpchan, next);
	}

	ISC_LIST_APPEND(list->channels, newc, next);

	/* replacing a predefined channel is a plain success.  */
	return (existed && !predefined ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logginglist_addcategory(dns_c_logginglist_t *list,
			      dns_c_logcat_t *newcat,
			      isc_boolean_t deepcopy)
{
	dns_c_logcat_t *newc, *tmpcat;
	isc_result_t res;
	isc_boolean_t existed = ISC_FALSE;
	isc_boolean_t predefined = ISC_FALSE;

	REQUIRE(DNS_C_LOGLIST_VALID(list));
	REQUIRE(DNS_C_LOGCAT_VALID(newcat));
	

	if (deepcopy) {
		res = dns_c_logcat_copy(list->mem, &newc, newcat);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		newc = newcat;
	}

	/* Remove old category defintion if there. */
	tmpcat = ISC_LIST_HEAD(list->categories);
	while (tmpcat != NULL) {
		if (strcmp(newcat->catname,tmpcat->catname) == 0) {
			existed = ISC_TRUE;
			predefined = tmpcat->predefined;
			
			ISC_LIST_UNLINK(list->categories, tmpcat, next);
			res = dns_c_logcat_delete(&tmpcat);
			if (res != ISC_R_SUCCESS) {
				if (deepcopy) {
					dns_c_logcat_delete(&newc);
				}
				return (res);
			}
			break;
		}

		tmpcat = ISC_LIST_NEXT(tmpcat, next);
	}

	ISC_LIST_APPEND(list->categories, newc, next);

	/* replacing a predefined category is a simple success. */
	return (existed && !predefined ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logginglist_delchannel(dns_c_logginglist_t *list,
			     const char *name)
{
	dns_c_logchan_t *logc;
	isc_result_t res;

	REQUIRE(DNS_C_LOGLIST_VALID(list));
	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');

	res = dns_c_logginglist_chanbyname(list, name, &logc);
	if (res == ISC_R_SUCCESS) {
		ISC_LIST_UNLINK(list->channels, logc, next);

		res = dns_c_logchan_delete(&logc);
	}

	return (res);
}


isc_result_t
dns_c_logginglist_delcategory(dns_c_logginglist_t *list,
			      const char *name)
{
	dns_c_logcat_t *logc;
	isc_result_t res;

	REQUIRE(DNS_C_LOGLIST_VALID(list));
	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');

	res = dns_c_logginglist_catbyname(list, name, &logc);
	if (res == ISC_R_SUCCESS) {
		ISC_LIST_UNLINK(list->categories, logc, next);

		res = dns_c_logcat_delete(&logc);
	}

	return (res);
}


isc_result_t
dns_c_logginglist_chanbyname(dns_c_logginglist_t *list,
			     const char *name,
			     dns_c_logchan_t **chan)
{
	dns_c_logchan_t *logc;

	REQUIRE(DNS_C_LOGLIST_VALID(list));
	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');
	REQUIRE(chan != NULL);

	logc = ISC_LIST_HEAD(list->channels);
	while (logc != NULL) {
		if (strcmp(logc->name, name) == 0) {
			break;
		}

		logc = ISC_LIST_NEXT(logc, next);
	}

	if (logc == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		*chan = logc;
		return (ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_logginglist_catbyname(dns_c_logginglist_t *list,
			    const char *name,
			    dns_c_logcat_t **cat)
{
	dns_c_logcat_t *logc;

	REQUIRE(DNS_C_LOGLIST_VALID(list));
	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');
	REQUIRE(cat != NULL);

	logc = ISC_LIST_HEAD(list->categories);
	while (logc != NULL) {
		if (strcmp(logc->catname, name) == 0) {
			break;
		}

		logc = ISC_LIST_NEXT(logc, next);
	}

	if (logc == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		*cat = logc;
		return (ISC_R_SUCCESS);
	}
}


#if 0

isc_result_t
dns_c_logginglist_catbytype(dns_c_logginglist_t *list,
			    dns_c_category_t cattype,
			    dns_c_logcat_t **cat)
{
	dns_c_logcat_t *logc;

	REQUIRE(DNS_C_LOGLIST_VALID(list));
	REQUIRE(cat != NULL);

	logc = ISC_LIST_HEAD(list->categories);
	while (logc != NULL) {
		if (logc->category == cattype) {
			break;
		}

		logc = ISC_LIST_NEXT(logc, next);
	}

	if (logc == NULL) {
		return (ISC_R_NOTFOUND);
	} else {
		*cat = logc;
		return (ISC_R_SUCCESS);
	}
}

#endif


/* ************************************************************************ */
/* **************************** LOGGING CHANNELS ************************** */
/* ************************************************************************ */

isc_result_t
dns_c_logchan_new(isc_mem_t *mem, const char *name,
		  dns_c_logchantype_t ctype,
		  dns_c_logchan_t **newchan)
{
	dns_c_logchan_t *newc;

	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');
	REQUIRE(newchan != NULL);

	newc = isc_mem_get(mem, sizeof *newc);
	if (newc == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newc->magic = DNS_C_LOGCHAN_MAGIC;
	newc->mem = mem;
	newc->ctype = ctype;
	newc->severity = dns_c_log_info;
	newc->debug_level = 0;
	newc->print_category = ISC_FALSE;
	newc->print_severity = ISC_FALSE;
	newc->print_time = ISC_FALSE;
	newc->predefined = ISC_FALSE;

	memset(&newc->setflags, 0x0, sizeof newc->setflags);

	ISC_LINK_INIT(newc, next);
	
	newc->name = isc_mem_strdup(mem, name);
	if (newc->name == NULL) {
		isc_mem_put(mem, newc, sizeof *newc);
		return (ISC_R_NOMEMORY);
	}
	
	switch (ctype) {
	case dns_c_logchan_file:
		newc->u.filec.path = NULL;
		break;

	case dns_c_logchan_syslog:
	case dns_c_logchan_null:
		break;
	}
	
	*newchan = newc;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_delete(dns_c_logchan_t **channel)
{
	dns_c_logchan_t *logc;

	REQUIRE(channel != NULL);
	REQUIRE(DNS_C_LOGCHAN_VALID(*channel));

	logc = *channel;

	isc_mem_free(logc->mem, logc->name);

	switch (logc->ctype) {
	case dns_c_logchan_file:
		if (logc->u.filec.path != NULL) {
			isc_mem_free(logc->mem, logc->u.filec.path);
		}
		break;

	case dns_c_logchan_syslog:
	case dns_c_logchan_null:
		break;
	}

	*channel = NULL;

	logc->magic = 0;
	isc_mem_put(logc->mem, logc, sizeof *logc);

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_copy(isc_mem_t *mem, dns_c_logchan_t **dest,
		   dns_c_logchan_t *src)
{
	dns_c_logchan_t *logc;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_LOGCHAN_VALID(src));

	res = dns_c_logchan_new(mem, src->name, src->ctype, &logc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	logc->severity = src->severity;
	logc->debug_level = src->debug_level;
	logc->print_category = src->print_category;
	logc->print_severity = src->print_severity;
	logc->print_time = src->print_time;
	logc->setflags = src->setflags;
	
	switch (logc->ctype) {
	case dns_c_logchan_file:
		logc->u.filec.path = isc_mem_strdup(mem, src->u.filec.path);
		logc->u.filec.versions = src->u.filec.versions;
		logc->u.filec.size = src->u.filec.size;
		break;

	case dns_c_logchan_syslog:
		logc->u.syslogc.facility = src->u.syslogc.facility;
		break;

	case dns_c_logchan_null:
		break;
	}

	*dest = logc;
	
	return (ISC_R_SUCCESS);
}


void
dns_c_logchan_print(FILE *fp, int indent, dns_c_logchan_t *logchan,
		    isc_boolean_t if_predef_too)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_LOGCHAN_VALID(logchan));

	if (logchan->predefined && !if_predef_too) {
		return;
	}
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "channel %s {\n", logchan->name) ;

	dns_c_printtabs(fp, indent + 1) ;
	switch (logchan->ctype) {
	case dns_c_logchan_file:
		fprintf(fp, "file \"%s\"",
			(logchan->u.filec.path == NULL ?
			 "No path defined" : logchan->u.filec.path));

		if (DNS_C_CHECKBIT(CHAN_VERSIONS_BIT, &logchan->setflags)) {
			fprintf(fp, " versions ");
			if (logchan->u.filec.versions == DNS_C_UNLIM_VERSIONS){
				fprintf(fp, "unlimited");
			} else {
				fprintf(fp, "%u", logchan->u.filec.versions);
			}
		}

		if (DNS_C_CHECKBIT(CHAN_SIZE_BIT, &logchan->setflags)) {
			fprintf(fp, " size ");
			dns_c_printinunits(fp, logchan->u.filec.size);
		}
		break;

	case dns_c_logchan_syslog:
		fprintf(fp, "syslog ");
		print_log_facility(fp, logchan->u.syslogc.facility);
		break;

	case dns_c_logchan_null:
		fputs("null", fp);
		break;
	}
	fprintf(fp, ";\n");

	if (DNS_C_CHECKBIT(CHAN_SEVERITY_BIT, &logchan->setflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "severity ");
		print_log_severity(fp, logchan->severity);
		if (logchan->severity == dns_c_log_debug &&
		    DNS_C_CHECKBIT(CHAN_DEBUG_LEVEL_BIT, &logchan->setflags)) {
			fprintf(fp, " %d", logchan->debug_level);
		}
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(CHAN_PSEV_BIT, &logchan->setflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "print-severity %s;\n",
			(logchan->print_severity ? "true" : "false"));
	}
	
	if (DNS_C_CHECKBIT(CHAN_PCAT_BIT, &logchan->setflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "print-category %s;\n",
			(logchan->print_category ? "true" : "false"));
	}
	
	if (DNS_C_CHECKBIT(CHAN_PTIME_BIT, &logchan->setflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "print-time %s;\n",
			(logchan->print_time ? "true" : "false"));
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_logchan_setpath(dns_c_logchan_t *channel, const char *path)
{
	isc_boolean_t existed = ISC_FALSE;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(path != NULL);
	REQUIRE(*path != '\0');

	if (channel->ctype != dns_c_logchan_file) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "This type of channel doesn't have a "
			      "path field");
		return (ISC_R_FAILURE);
	}

	if (channel->u.filec.path != NULL) {
		existed = ISC_TRUE;
		isc_mem_free(channel->mem, channel->u.filec.path);
	}

	channel->u.filec.path = isc_mem_strdup(channel->mem, path);
	if (channel->u.filec.path == NULL) {
		return (ISC_R_NOMEMORY);
	} else {
		return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
	}
}


isc_result_t
dns_c_logchan_setversions(dns_c_logchan_t *channel, isc_uint32_t versions)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	existed = DNS_C_CHECKBIT(CHAN_VERSIONS_BIT, &channel->setflags);

	if (channel->ctype != dns_c_logchan_file) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "This type of channel doesn't have a "
			      "version field");
		return (ISC_R_FAILURE);
	}

	DNS_C_SETBIT(CHAN_VERSIONS_BIT, &channel->setflags);
	channel->u.filec.versions = versions;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_setsize(dns_c_logchan_t *channel, isc_uint32_t size)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	if (channel->ctype != dns_c_logchan_file) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "This type of channel doesn't have a "
			      "size field");
		return (ISC_R_FAILURE);
	}

	existed = DNS_C_CHECKBIT(CHAN_SIZE_BIT, &channel->setflags);

	DNS_C_SETBIT(CHAN_SIZE_BIT, &channel->setflags);
	channel->u.filec.size = size;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_setfacility(dns_c_logchan_t *channel, int facility)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	if (channel->ctype != dns_c_logchan_syslog) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "This type of channel doesn't have a "
			      "facility field");
		return (ISC_R_FAILURE);
	}

	
	if (dns_c_facility2string(facility, ISC_FALSE) == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Not a legal facility for a syslog channel: %d",
			      facility);
		return (ISC_R_FAILURE);
	}
	

	existed = DNS_C_CHECKBIT(CHAN_FACILITY_BIT, &channel->setflags);

	DNS_C_SETBIT(CHAN_FACILITY_BIT, &channel->setflags);
	channel->u.syslogc.facility = facility;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_setseverity(dns_c_logchan_t *channel,
			  dns_c_logseverity_t severity)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	existed = DNS_C_CHECKBIT(CHAN_SEVERITY_BIT, &channel->setflags);

	DNS_C_SETBIT(CHAN_SEVERITY_BIT, &channel->setflags);
	channel->severity = severity;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_setdebuglevel(dns_c_logchan_t *channel, isc_int32_t level)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	if (channel->severity == dns_c_log_debug) {
		existed = DNS_C_CHECKBIT(CHAN_DEBUG_LEVEL_BIT,
					 &channel->setflags);
		
		DNS_C_SETBIT(CHAN_DEBUG_LEVEL_BIT, &channel->setflags);
		channel->debug_level = level;
		
		return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
	} else {
		return (ISC_R_FAILURE);
	}
}


isc_result_t
dns_c_logchan_setprintcat(dns_c_logchan_t *channel, isc_boolean_t newval)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	existed = DNS_C_CHECKBIT(CHAN_PCAT_BIT, &channel->setflags);

	DNS_C_SETBIT(CHAN_PCAT_BIT, &channel->setflags);
	channel->print_category = newval;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_setprintsev(dns_c_logchan_t *channel, isc_boolean_t newval)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	existed = DNS_C_CHECKBIT(CHAN_PSEV_BIT, &channel->setflags);

	DNS_C_SETBIT(CHAN_PSEV_BIT, &channel->setflags);
	channel->print_severity = newval;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_logchan_setprinttime(dns_c_logchan_t *channel, isc_boolean_t newval)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	existed = DNS_C_CHECKBIT(CHAN_PTIME_BIT, &channel->setflags);

	DNS_C_SETBIT(CHAN_PTIME_BIT, &channel->setflags);
	channel->print_time = newval;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}

isc_result_t
dns_c_logchan_setpredef(dns_c_logchan_t *channel, isc_boolean_t newval)
{
	REQUIRE(DNS_C_LOGCHAN_VALID(channel));

	channel->predefined = newval;

	return (ISC_R_SUCCESS);
}





isc_result_t
dns_c_logchan_getpath(dns_c_logchan_t *channel, const char **path)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(path != NULL);

	if (channel->ctype == dns_c_logchan_file &&
	    channel->u.filec.path != NULL) {
		*path = channel->u.filec.path;
		res = ISC_R_SUCCESS;
	} else if (channel->ctype == dns_c_logchan_file) {
		res = ISC_R_NOTFOUND;
	} else {
		res = ISC_R_FAILURE;
	}

	return (res);
}


isc_result_t
dns_c_logchan_getversions(dns_c_logchan_t *channel, isc_uint32_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (channel->ctype == dns_c_logchan_file &&
	    DNS_C_CHECKBIT(CHAN_VERSIONS_BIT, &channel->setflags)) {
		*retval = channel->u.filec.versions;
		res = ISC_R_SUCCESS;
	} else if (channel->ctype == dns_c_logchan_file) {
		res = ISC_R_NOTFOUND;
	} else {
		res = ISC_R_FAILURE;
	}

	return (res);
}


isc_result_t
dns_c_logchan_getsize(dns_c_logchan_t *channel, isc_uint32_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (channel->ctype == dns_c_logchan_file &&
	    DNS_C_CHECKBIT(CHAN_SIZE_BIT, &channel->setflags)) {
		*retval = channel->u.filec.size;
		res = ISC_R_SUCCESS;
	} else if (channel->ctype == dns_c_logchan_file) {
		res = ISC_R_NOTFOUND;
	} else {
		res = ISC_R_FAILURE;
	}

	return (res);
}


isc_result_t
dns_c_logchan_getfacility(dns_c_logchan_t *channel, int *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (channel->ctype == dns_c_logchan_syslog &&
	    DNS_C_CHECKBIT(CHAN_FACILITY_BIT, &channel->setflags)) {
		*retval = channel->u.syslogc.facility;
		res = ISC_R_SUCCESS;
	} else if (channel->ctype == dns_c_logchan_syslog) {
		res = ISC_R_NOTFOUND;
	} else {
		res = ISC_R_FAILURE;
	}

	return (res);

}


isc_result_t
dns_c_logchan_getseverity(dns_c_logchan_t *channel,
			  dns_c_logseverity_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(CHAN_SEVERITY_BIT, &channel->setflags)) {
		*retval = channel->severity;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_logchan_getdebuglevel(dns_c_logchan_t *channel, isc_int32_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(CHAN_DEBUG_LEVEL_BIT, &channel->setflags)) {
		*retval = channel->debug_level;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_logchan_getprintcat(dns_c_logchan_t *channel, isc_boolean_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(CHAN_PCAT_BIT, &channel->setflags)) {
		*retval = channel->print_category;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_logchan_getprintsev(dns_c_logchan_t *channel, isc_boolean_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(CHAN_PSEV_BIT, &channel->setflags)) {
		*retval = channel->print_severity;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);

}


isc_result_t
dns_c_logchan_getprinttime(dns_c_logchan_t *channel, isc_boolean_t *retval)
{
	isc_result_t res;

	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(CHAN_PTIME_BIT, &channel->setflags)) {
		*retval = channel->print_time;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_logchan_getpredef(dns_c_logchan_t *channel, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_LOGCHAN_VALID(channel));
	REQUIRE(retval != NULL);

	*retval = channel->predefined;

	return (ISC_R_SUCCESS);
}


/*
 * Logging category
 */
isc_result_t
dns_c_logcat_new(isc_mem_t *mem, const char *name, dns_c_logcat_t **newlc)
{
	dns_c_logcat_t *newc;
	unsigned int i;

	REQUIRE(newlc != NULL);

	newc = isc_mem_get(mem, sizeof *newc);
	if (newc == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newc->magic = DNS_C_LOGCAT_MAGIC;
	newc->mem = mem;
	newc->catname = isc_mem_strdup(mem, name);
	newc->cnames_len = 2;
	newc->nextcname = 0;
	newc->predefined = ISC_FALSE;
	newc->channel_names = isc_mem_get(mem,
					  sizeof (char *) * newc->cnames_len);
	if (newc->channel_names == NULL) {
		isc_mem_put(mem, newc, sizeof *newc);
		return (ISC_R_NOMEMORY);
	}

	for (i = 0 ; i < newc->cnames_len ; i++) {
		newc->channel_names[i] = NULL;
	}

	*newlc = newc;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logcat_delete(dns_c_logcat_t **logcat)
{
	dns_c_logcat_t *logc;
	unsigned int i;

	REQUIRE(logcat != NULL);
	REQUIRE(DNS_C_LOGCAT_VALID(*logcat));

	logc = *logcat;
	if (logc == NULL) {
		return (ISC_R_SUCCESS);
	}

	for (i = 0 ; i < logc->nextcname ; i++) {
		REQUIRE(logc->channel_names[i] != NULL);

		isc_mem_free(logc->mem, logc->channel_names[i]);
	}

	logc->magic = 0;
	isc_mem_free(logc->mem, logc->catname);
	isc_mem_put(logc->mem, logc->channel_names,
		    sizeof (char *) * logc->cnames_len);
	isc_mem_put(logc->mem, logc, sizeof *logc);

	*logcat = NULL;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logcat_copy(isc_mem_t *mem, dns_c_logcat_t **dest, dns_c_logcat_t *src)
{
	unsigned int i;
	dns_c_logcat_t *newc;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_LOGCAT_VALID(src));

	res = dns_c_logcat_new(mem, src->catname, &newc);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	for (i = 0 ; i < src->nextcname ; i++) {
		res = dns_c_logcat_addname(newc, src->channel_names[i]);
		if (res != ISC_R_SUCCESS) {
			dns_c_logcat_delete(&newc);
			return (res);
		}
	}

	return (ISC_R_SUCCESS);
}


void
dns_c_logcat_print(FILE *fp, int indent, dns_c_logcat_t *logcat,
		   isc_boolean_t if_predef_too)
{
	unsigned int i;
	
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_LOGCAT_VALID(logcat));

	if (logcat->predefined && !if_predef_too) {
		return;
	}
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "category %s {\n", logcat->catname);

	for (i = 0 ; i < logcat->nextcname ; i++) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "%s;\n", logcat->channel_names[i]);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_logcat_addname(dns_c_logcat_t *logcat, const char *name)
{
	unsigned int i;

	REQUIRE(DNS_C_LOGCAT_VALID(logcat));
	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');

	if (logcat->cnames_len == logcat->nextcname) {
		size_t newsize = logcat->cnames_len + 5;
		char **newarr = isc_mem_get(logcat->mem,
					    newsize * sizeof (char *));

		if (newarr == NULL) {
			return (ISC_R_NOMEMORY);
		}

		for (i = 0 ; i < newsize ; i++) {
			if (i < logcat->cnames_len) {
				newarr[i] = logcat->channel_names[i];
			} else {
				newarr[i] = NULL;
			}
		}

		isc_mem_put(logcat->mem, logcat->channel_names,
			    sizeof (char *) * logcat->cnames_len);

		logcat->channel_names = newarr;
		logcat->cnames_len = newsize;
	}

	logcat->channel_names[logcat->nextcname] =
		isc_mem_strdup(logcat->mem, name);
	if (logcat->channel_names[logcat->nextcname] == NULL) {
		return (ISC_R_NOMEMORY);
	}

	logcat->nextcname++;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logcat_delname(dns_c_logcat_t *logcat, const char *name)
{
	unsigned int i ;
	isc_result_t res;

	REQUIRE(DNS_C_LOGCAT_VALID(logcat));
	REQUIRE(name != NULL);
	REQUIRE(*name != '\0');

	for (i = 0 ; i < logcat->nextcname ; i++) {
		INSIST(logcat->channel_names[i] != NULL);
		if (strcmp(logcat->channel_names[i], name) == 0) {
			break;
		}
	}

	if (i < logcat->nextcname) {
		res = ISC_R_SUCCESS;
		isc_mem_free(logcat->mem, logcat->channel_names[i]);
		while (i < (logcat->nextcname - 1)) {
			logcat->channel_names[i] = logcat->channel_names[i+1];
			i++;
		}
	} else {
		res = ISC_R_NOTFOUND;
	}


	return (res);
}



isc_result_t
dns_c_logcat_setpredef(dns_c_logcat_t *logcat,isc_boolean_t newval)
{
	REQUIRE(DNS_C_LOGCAT_VALID(logcat));

	logcat->predefined = newval;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_logcat_getpredef(dns_c_logcat_t *logcat, isc_boolean_t *retval)
{
	REQUIRE(DNS_C_LOGCAT_VALID(logcat));
	REQUIRE(retval != NULL);

	*retval = logcat->predefined;

	return (ISC_R_SUCCESS);
}




/***************************************************************************/


static void
print_log_facility(FILE *fp, int value)
{
	REQUIRE(fp != NULL);
	
	fputs(dns_c_facility2string(value, ISC_TRUE), fp);
}


static void
print_log_severity(FILE *fp, dns_c_logseverity_t severity)
{
	REQUIRE(fp != NULL);
	
	fputs(dns_c_logseverity2string(severity, ISC_TRUE), fp);
}


