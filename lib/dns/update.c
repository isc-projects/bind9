/*
 * Copyright
 */

#include "config.h"

#include <isc/stdtime.h>
#include <isc/serial.h>

#include <dns/update.h>

isc_uint32_t
dns_update_soaserial(isc_uint32_t serial, dns_updatemethod_t method) {
	isc_stdtime_t now;

        if (method == dns_updatemethod_unixtime) {
		isc_stdtime_get(&now);
	        if (now != 0 && isc_serial_gt(now, serial))
                	return (now);
	}

	/* RFC1982 */
	serial = (serial + 1) & 0xFFFFFFFF;
	if (serial == 0)
		serial = 1;

	return (serial);
}
