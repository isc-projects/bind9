/*
 * Copyright
 */

/* $Id: check-tool.h,v 1.1 2000/12/14 21:33:11 marka Exp $ */

#ifndef CHECK_TOOL_H
#define CHECK_TOOL_H

#include <isc/lang.h>

#include <isc/types.h>

ISC_LANG_BEGINDECLS

isc_result_t
setup_logging(isc_mem_t *mctx, isc_log_t **logp);

ISC_LANG_ENDDECLS

#endif
