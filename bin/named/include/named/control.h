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
