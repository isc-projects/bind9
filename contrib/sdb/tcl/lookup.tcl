#
# Sample lookup procedure for tcldb
#

proc lookup {zone name} {
    global dbargs
    puts $zone
    switch -- $name {
	@ { return [list \
		{SOA 86400 "ns.isp.nil. hostmaster.isp.nil. 0 3600 1800 1814400 3600"} \
		{NS 86400 "ns1"} \
		{NS 86400 "ns2"} \
		{MX 86400 "10 mail.isp.nil."} ] }
	www { return [list [list A 3600 $dbargs($zone)] ] }
    }
    return NXDOMAIN
}
