/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


/*! \file */

#include <config.h>

#include <stdbool.h>
#include <isc/app.h>
#include <isc/event.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/result.h>

#include <isccc/alist.h>
#include <isccc/cc.h>
#include <isccc/result.h>

#include <named/control.h>
#include <named/globals.h>
#include <named/log.h>
#include <named/os.h>
#include <named/server.h>
#ifdef HAVE_LIBSCF
#include <named/ns_smf_globals.h>
#endif

static isc_result_t
getcommand(isc_lex_t *lex, char **cmdp) {
	isc_result_t result;
	isc_token_t token;

	REQUIRE(cmdp != NULL && *cmdp == NULL);

	result = isc_lex_gettoken(lex, ISC_LEXOPT_EOF, &token);
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_lex_ungettoken(lex, &token);

	if (token.type != isc_tokentype_string)
		return (ISC_R_FAILURE);

	*cmdp = token.value.as_textregion.base;

	return (ISC_R_SUCCESS);
}

static inline bool
command_compare(const char *str, const char *command) {
	return (strcasecmp(str, command) == 0);
}

/*%
 * This function is called to process the incoming command
 * when a control channel message is received.
 */
isc_result_t
ns_control_docommand(isccc_sexpr_t *message, bool readonly,
		     isc_buffer_t **text)
{
	isccc_sexpr_t *data;
	char *cmdline = NULL;
	char *command = NULL;
	isc_result_t result;
	int log_level;
	isc_buffer_t src;
	isc_lex_t *lex = NULL;
#ifdef HAVE_LIBSCF
	ns_smf_want_disable = 0;
#endif

	data = isccc_alist_lookup(message, "_data");
	if (!isccc_alist_alistp(data)) {
		/*
		 * No data section.
		 */
		return (ISC_R_FAILURE);
	}

	result = isccc_cc_lookupstring(data, "type", &cmdline);
	if (result != ISC_R_SUCCESS) {
		/*
		 * We have no idea what this is.
		 */
		return (result);
	}

	result = isc_lex_create(ns_g_mctx, strlen(cmdline), &lex);
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_buffer_init(&src, cmdline, strlen(cmdline));
	isc_buffer_add(&src, strlen(cmdline));
	result = isc_lex_openbuffer(lex, &src);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = getcommand(lex, &command);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * Compare the 'command' parameter against all known control commands.
	 */
	if ((command_compare(command, NS_COMMAND_NULL) &&
	     strlen(cmdline) == 4) ||
	    command_compare(command, NS_COMMAND_STATUS))
	{
		log_level = ISC_LOG_DEBUG(1);
	} else {
		log_level = ISC_LOG_INFO;
	}

	/*
	 * If this listener should have read-only access, reject
	 * restricted commands here. rndc nta is handled specially
	 * below.
	 */
	if (readonly &&
	    !command_compare(command, NS_COMMAND_NTA) &&
	    !command_compare(command, NS_COMMAND_NULL) &&
	    !command_compare(command, NS_COMMAND_STATUS) &&
	    !command_compare(command, NS_COMMAND_SHOWZONE) &&
	    !command_compare(command, NS_COMMAND_TESTGEN) &&
	    !command_compare(command, NS_COMMAND_ZONESTATUS))
	{
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, log_level,
			      "rejecting restricted control channel "
			      "command '%s'", cmdline);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_CONTROL, log_level,
		      "received control channel command '%s'",
		      cmdline);

	/*
	 * After the lengthy "halt" and "stop", the commands are
	 * handled in alphabetical order of the NS_COMMAND_ macros.
	 */
	if (command_compare(command, NS_COMMAND_HALT)) {
#ifdef HAVE_LIBSCF
		/*
		 * If we are managed by smf(5), AND in chroot, then
		 * we cannot connect to the smf repository, so just
		 * return with an appropriate message back to rndc.
		 */
		if (ns_smf_got_instance == 1 && ns_smf_chroot == 1) {
			result = ns_smf_add_message(text);
			goto cleanup;
		}
		/*
		 * If we are managed by smf(5) but not in chroot,
		 * try to disable ourselves the smf way.
		 */
		if (ns_smf_got_instance == 1 && ns_smf_chroot == 0)
			ns_smf_want_disable = 1;
		/*
		 * If ns_smf_got_instance = 0, ns_smf_chroot
		 * is not relevant and we fall through to
		 * isc_app_shutdown below.
		 */
#endif
		/* Do not flush master files */
		ns_server_flushonshutdown(ns_g_server, false);
		ns_os_shutdownmsg(cmdline, *text);
		isc_app_shutdown();
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_STOP)) {
		/*
		 * "stop" is the same as "halt" except it does
		 * flush master files.
		 */
#ifdef HAVE_LIBSCF
		if (ns_smf_got_instance == 1 && ns_smf_chroot == 1) {
			result = ns_smf_add_message(text);
			goto cleanup;
		}
		if (ns_smf_got_instance == 1 && ns_smf_chroot == 0)
			ns_smf_want_disable = 1;
#endif
		ns_server_flushonshutdown(ns_g_server, true);
		ns_os_shutdownmsg(cmdline, *text);
		isc_app_shutdown();
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_ADDZONE) ||
		   command_compare(command, NS_COMMAND_MODZONE)) {
		result = ns_server_changezone(ns_g_server, cmdline, text);
	} else if (command_compare(command, NS_COMMAND_DELZONE)) {
		result = ns_server_delzone(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_DNSTAP) ||
		   command_compare(command, NS_COMMAND_DNSTAPREOPEN)) {
		result = ns_server_dnstap(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_DUMPDB)) {
		ns_server_dumpdb(ns_g_server, lex, text);
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_DUMPSTATS)) {
		result = ns_server_dumpstats(ns_g_server);
	} else if (command_compare(command, NS_COMMAND_FLUSH)) {
		result = ns_server_flushcache(ns_g_server, lex);
	} else if (command_compare(command, NS_COMMAND_FLUSHNAME)) {
		result = ns_server_flushnode(ns_g_server, lex, false);
	} else if (command_compare(command, NS_COMMAND_FLUSHTREE)) {
		result = ns_server_flushnode(ns_g_server, lex, true);
	} else if (command_compare(command, NS_COMMAND_FREEZE)) {
		result = ns_server_freeze(ns_g_server, true, lex,
					  text);
	} else if (command_compare(command, NS_COMMAND_LOADKEYS) ||
		   command_compare(command, NS_COMMAND_SIGN)) {
		result = ns_server_rekey(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_MKEYS)) {
		result = ns_server_mkeys(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_NOTIFY)) {
		result = ns_server_notifycommand(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_NOTRACE)) {
		ns_g_debuglevel = 0;
		isc_log_setdebuglevel(ns_g_lctx, ns_g_debuglevel);
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_NTA)) {
		result = ns_server_nta(ns_g_server, lex, readonly, text);
	} else if (command_compare(command, NS_COMMAND_NULL)) {
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_QUERYLOG)) {
		result = ns_server_togglequerylog(ns_g_server, lex);
	} else if (command_compare(command, NS_COMMAND_RECONFIG)) {
		result = ns_server_reconfigcommand(ns_g_server);
	} else if (command_compare(command, NS_COMMAND_RECURSING)) {
		result = ns_server_dumprecursing(ns_g_server);
	} else if (command_compare(command, NS_COMMAND_REFRESH)) {
		result = ns_server_refreshcommand(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_RELOAD)) {
		result = ns_server_reloadcommand(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_RETRANSFER)) {
		result = ns_server_retransfercommand(ns_g_server,
						     lex, text);
	} else if (command_compare(command, NS_COMMAND_SCAN)) {
		result = ISC_R_SUCCESS;
		ns_server_scan_interfaces(ns_g_server);
	} else if (command_compare(command, NS_COMMAND_SECROOTS)) {
		result = ns_server_dumpsecroots(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_SIGNING)) {
		result = ns_server_signing(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_SHOWZONE)) {
		result = ns_server_showzone(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_STATUS)) {
		result = ns_server_status(ns_g_server, text);
	} else if (command_compare(command, NS_COMMAND_SYNC)) {
		result = ns_server_sync(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_THAW) ||
		   command_compare(command, NS_COMMAND_UNFREEZE)) {
		result = ns_server_freeze(ns_g_server, false, lex,
					  text);
	} else if (command_compare(command, NS_COMMAND_TESTGEN)) {
		result = ns_server_testgen(lex, text);
	} else if (command_compare(command, NS_COMMAND_TIMERPOKE)) {
		result = ISC_R_SUCCESS;
		isc_timermgr_poke(ns_g_timermgr);
	} else if (command_compare(command, NS_COMMAND_TRACE)) {
		result = ns_server_setdebuglevel(ns_g_server, lex);
	} else if (command_compare(command, NS_COMMAND_TSIGDELETE)) {
		result = ns_server_tsigdelete(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_TSIGLIST)) {
		result = ns_server_tsiglist(ns_g_server, text);
	} else if (command_compare(command, NS_COMMAND_VALIDATION)) {
		result = ns_server_validation(ns_g_server, lex, text);
	} else if (command_compare(command, NS_COMMAND_ZONESTATUS)) {
		result = ns_server_zonestatus(ns_g_server, lex, text);
	} else {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "unknown control channel command '%s'",
			      command);
		result = DNS_R_UNKNOWNCOMMAND;
	}

 cleanup:
	if (lex != NULL)
		isc_lex_destroy(&lex);

	return (result);
}
