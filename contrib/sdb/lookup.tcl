# Copyright (C) 2000  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: lookup.tcl,v 1.5 2000/11/18 01:35:05 gson Exp $

#
# Sample lookup procedure for tcldb
#

proc lookup {zone name} {
    global dbargs
    switch -- $name {
	@ { return [list \
		{SOA 86400 "ns1.isp.nil. hostmaster.isp.nil. \
		    0 3600 1800 1814400 3600"} \
		{NS 86400 "ns1.isp.nil."} \
		{NS 86400 "ns2.isp.nil."} \
		{MX 86400 "10 mail.isp.nil."} ] }
	www { return [list [list A 3600 $dbargs($zone)] ] }
    }
    return NXDOMAIN
}
