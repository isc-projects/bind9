#include <port_before.h>

#include <sys/types.h>
#include <sys/param.h>
#if (!defined(BSD)) || (BSD < 199306)
#include <sys/bitypes.h>
#endif
#include <netinet/in.h>
#include <port_after.h>

/*
 * Make sure we don't cause linkage problems.
 */
const struct in6_addr isc_in6addr_any = IN6ADDR_ANY_INIT;
#if 0
const struct in6_addr isc_in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
#endif
