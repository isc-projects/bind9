/*
 * Copyright (C) 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: control.h,v 1.3 2001/04/11 20:37:36 bwelling Exp $ */

#ifndef NAMED_CONTROL_H
#define NAMED_CONTROL_H 1

#include <isccc/types.h>

#include <named/aclconf.h>

#define NS_CONTROL_PORT			953

#define NS_COMMAND_STOP		"stop"
#define NS_COMMAND_HALT		"halt"
#define NS_COMMAND_RELOAD	"reload"
#define NS_COMMAND_RELOADCONFIG	"reload-config"
#define NS_COMMAND_RELOADZONES	"reload-zones"
#define NS_COMMAND_REFRESH	"refresh"
#define NS_COMMAND_DUMPSTATS	"stats"
#define NS_COMMAND_QUERYLOG	"querylog"
#define NS_COMMAND_DUMPDB	"dumpdb"
#define NS_COMMAND_TRACE	"trace"
#define NS_COMMAND_NOTRACE	"notrace"
#define NS_COMMAND_FLUSH	"flush"

isc_result_t
ns_control_init(void);

isc_result_t
ns_control_configure(isc_mem_t *mctx, cfg_obj_t *config,
		     ns_aclconfctx_t *aclconfctx);

void
ns_control_shutdown(isc_boolean_t exiting);

isc_result_t
ns_control_docommand(isccc_sexpr_t *message);

#endif /* NAMED_CONTROL_H */
