#!/usr/bin/perl

use FileHandle;

my $masterconf = new FileHandle("ns1/zones.conf", "w") or die;
my $slaveconf  = new FileHandle("ns2/zones.conf", "w") or die;

for ($z = 0; $z < 1000; $z++) {
    my $zn = sprintf("zone%06d.example", $z);
    print $masterconf "zone \"$zn\" { type master; file \"$zn.db\"; };\n";
    print $slaveconf  "zone \"$zn\" { type slave; file \"$zn.bk\"; masters { 10.53.0.1; }; };\n";
    my $f = new FileHandle("ns1/$zn.db", "w") or die;
    print $f "\$TTL 300
\@	IN SOA 	. . 1 9999 9999 99999 999
	NS	ns1
	NS	ns2
	MX	10 mail1.isp.example.
	MX	20 mail2.isp.example.
www	A	10.0.0.1
xyzzy   A       10.0.0.2
";
    $f->close;
}
