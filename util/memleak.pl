#!/usr/bin/perl

# Massage the output from ISC_MEM_DEBUG to extract mem_get() calls
# with no corresponding mem_put().

$mem_stats = '';

while (<>) {
    $gets{$1.$2} = $_ if /mem(pool)?_get.*-> 0x([0-9a-f]+)/;
    delete $gets{$1.$2} if /mem(pool)?_put\(0x[0-9a-f]+, 0x([0-9a-f]+)/;
    $mem_stats .= $_ if /\d+ gets, +(\d+) rem/ && $1 > 0;
}
print join('', values %gets);
print $mem_stats;

exit(0);
