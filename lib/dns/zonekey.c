#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/keyvalues.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <dns/types.h>
#include <dns/zonekey.h>

isc_boolean_t
dns_zonekey_iszonekey(dns_rdata_t *keyrdata) {
	isc_result_t result;
	dns_rdata_key_t key;
	isc_boolean_t iszonekey = ISC_TRUE;

	REQUIRE(keyrdata != NULL);

	result = dns_rdata_tostruct(keyrdata, &key, NULL);
	if (result != ISC_R_SUCCESS)
		return (ISC_FALSE);

	if ((key.flags & DNS_KEYTYPE_NOAUTH) != 0)
		iszonekey = ISC_FALSE;
	if ((key.flags & DNS_KEYFLAG_OWNERMASK) != DNS_KEYOWNER_ZONE)
		iszonekey = ISC_FALSE;
	if (key.protocol != DNS_KEYPROTO_DNSSEC &&
	key.protocol != DNS_KEYPROTO_ANY)
		iszonekey = ISC_FALSE;
	
	return (iszonekey);
}
