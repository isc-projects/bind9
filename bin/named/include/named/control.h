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

#ifndef NAMED_CONTROL_H
#define NAMED_CONTROL_H 1

/*! \file
 * \brief
 * The name server command channel.
 */

#include <stdbool.h>
#include <isccc/types.h>

#include <isccfg/aclconf.h>

#include <named/types.h>

#define NS_CONTROL_PORT			953

#define NS_COMMAND_STOP		"stop"
#define NS_COMMAND_HALT		"halt"
#define NS_COMMAND_RELOAD	"reload"
#define NS_COMMAND_RECONFIG	"reconfig"
#define NS_COMMAND_REFRESH	"refresh"
#define NS_COMMAND_RETRANSFER	"retransfer"
#define NS_COMMAND_DUMPSTATS	"stats"
#define NS_COMMAND_QUERYLOG	"querylog"
#define NS_COMMAND_DUMPDB	"dumpdb"
#define NS_COMMAND_SECROOTS	"secroots"
#define NS_COMMAND_TRACE	"trace"
#define NS_COMMAND_NOTRACE	"notrace"
#define NS_COMMAND_FLUSH	"flush"
#define NS_COMMAND_FLUSHNAME	"flushname"
#define NS_COMMAND_FLUSHTREE	"flushtree"
#define NS_COMMAND_STATUS	"status"
#define NS_COMMAND_TSIGLIST	"tsig-list"
#define NS_COMMAND_TSIGDELETE	"tsig-delete"
#define NS_COMMAND_FREEZE	"freeze"
#define NS_COMMAND_UNFREEZE	"unfreeze"
#define NS_COMMAND_THAW		"thaw"
#define NS_COMMAND_TIMERPOKE	"timerpoke"
#define NS_COMMAND_RECURSING	"recursing"
#define NS_COMMAND_NULL		"null"
#define NS_COMMAND_NOTIFY	"notify"
#define NS_COMMAND_VALIDATION	"validation"
#define NS_COMMAND_SCAN 	"scan"
#define NS_COMMAND_SIGN 	"sign"
#define NS_COMMAND_LOADKEYS 	"loadkeys"
#define NS_COMMAND_ADDZONE	"addzone"
#define NS_COMMAND_MODZONE	"modzone"
#define NS_COMMAND_DELZONE	"delzone"
#define NS_COMMAND_SHOWZONE	"showzone"
#define NS_COMMAND_SYNC		"sync"
#define NS_COMMAND_SIGNING	"signing"
#define NS_COMMAND_ZONESTATUS	"zonestatus"
#define NS_COMMAND_NTA		"nta"
#define NS_COMMAND_TESTGEN	"testgen"
#define NS_COMMAND_MKEYS	"managed-keys"
#define NS_COMMAND_DNSTAPREOPEN	"dnstap-reopen"
#define NS_COMMAND_DNSTAP	"dnstap"

isc_result_t
ns_controls_create(ns_server_t *server, ns_controls_t **ctrlsp);
/*%<
 * Create an initial, empty set of command channels for 'server'.
 */

void
ns_controls_destroy(ns_controls_t **ctrlsp);
/*%<
 * Destroy a set of command channels.
 *
 * Requires:
 *	Shutdown of the channels has completed.
 */

isc_result_t
ns_controls_configure(ns_controls_t *controls, const cfg_obj_t *config,
		      cfg_aclconfctx_t *aclconfctx);
/*%<
 * Configure zero or more command channels into 'controls'
 * as defined in the configuration parse tree 'config'.
 * The channels will evaluate ACLs in the context of
 * 'aclconfctx'.
 */

void
ns_controls_shutdown(ns_controls_t *controls);
/*%<
 * Initiate shutdown of all the command channels in 'controls'.
 */

isc_result_t
ns_control_docommand(isccc_sexpr_t *message, bool readonly,
		     isc_buffer_t **text);

#endif /* NAMED_CONTROL_H */
