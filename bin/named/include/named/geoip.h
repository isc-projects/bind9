#ifndef _GEOIP_H
#define _GEOIP_H

#ifdef HAVE_GEOIP
#include <GeoIP.h>
#include <GeoIPCity.h>

void ns_geoip_init(void);
void ns_geoip_load(char *dir);

extern dns_geoip_databases_t *ns_g_geoip;

#endif /* HAVE_GEOIP */
#endif
