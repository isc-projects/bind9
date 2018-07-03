#include <stddef.h>
#include <stdint.h>
#include <isc/buffer.h>
#include <dns/fixedname.h>
#include <dns/name.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    isc_buffer_t buf;
    isc_result_t result;
    dns_fixedname_t origin;
    if (size < 5) return 0;

    dns_fixedname_init(&origin);    
    isc_buffer_init(&buf, (void *)data, size);
    isc_buffer_add(&buf, size);
    result = dns_name_fromtext(dns_fixedname_name(&origin), &buf, dns_rootname, 0, NULL);
    return 0;
}
