#include <config.h>

#include <string.h>

#include <isc/app.h>
#include <isc/event.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <isccc/alist.h>
#include <isccc/cc.h>
#include <isccc/result.h>

#include <named/control.h>
#include <named/log.h>
#include <named/server.h>

static isc_boolean_t
command_compare(const char *text, const char *command) {
	if (strncasecmp(text, command, strlen(command)) == 0 &&
	    (text[strlen(command)] == 0 || text[strlen(command)] == ' '))
		return (ISC_TRUE);
	return (ISC_FALSE);
}

/*
 * This is the function that is called to process an incoming command when a
 * message is received.  It is called once for each name/value pair in the
 * message's object value list or something.
 */
isc_result_t
ns_control_docommand(isccc_sexpr_t *message) {
	isccc_sexpr_t *data;
	char *command;
	isc_result_t result;

	data = isccc_alist_lookup(message, "_data");
	if (data == NULL) {
		/*
		 * No data section.
		 */
		return (ISC_R_FAILURE);
	}

	result = isccc_cc_lookupstring(data, "type", &command);
	if (result != ISC_R_SUCCESS) {
		/*
		 * We have no idea what this is.
		 */
		return (result);
	}

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_CONTROL, ISC_LOG_DEBUG(1),
		      "received control channel command '%s'",
		      command);

	/*
	 * Compare the 'command' parameter against all known control commands.
	 */
	if (command_compare(command, NS_COMMAND_RELOAD)) {
		result = ns_server_reloadcommand(ns_g_server, command);
	} else if (command_compare(command, NS_COMMAND_REFRESH)) {
		result = ns_server_refreshcommand(ns_g_server, command);
	} else if (command_compare(command, NS_COMMAND_HALT)) {
		ns_server_flushonshutdown(ns_g_server, ISC_FALSE);
		isc_app_shutdown();
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_STOP)) {
		ns_server_flushonshutdown(ns_g_server, ISC_TRUE);
		isc_app_shutdown();
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_RELOADCONFIG) ||
		   command_compare(command, NS_COMMAND_RELOADZONES)) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "unimplemented channel command '%s'",
			      command);
		result = ISC_R_NOTIMPLEMENTED;
	} else if (command_compare(command, NS_COMMAND_DUMPSTATS)) {
		result = ns_server_dumpstats(ns_g_server);
	} else if (command_compare(command, NS_COMMAND_QUERYLOG)) {
		result = ns_server_togglequerylog(ns_g_server);
	} else if (command_compare(command, NS_COMMAND_DUMPDB)) {
		ns_server_dumpdb(ns_g_server);
		result = ISC_R_SUCCESS;
	} else if (command_compare(command, NS_COMMAND_TRACE)) {
		result = ns_server_setdebuglevel(ns_g_server, command);
	} else if (command_compare(command, NS_COMMAND_NOTRACE)) {
		ns_g_debuglevel = 0;
		isc_log_setdebuglevel(ns_g_lctx, ns_g_debuglevel);
		result = ISC_R_SUCCESS;
	} else {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "unknown control channel command '%s'",
			      command);
		result = ISC_R_NOTIMPLEMENTED;
	}

	return (result);
}
