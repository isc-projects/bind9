#!/bin/sh
#
# Set up interface aliases for bind9 system tests.
#

sys=`../../../config.guess`
case "$sys" in 
    sparc-sun-solaris2.6)
    sparc-sun-solaris2.7)
    sparc-sun-solaris2.8)
	type="lo0"
	;;
    i686-pc-linux-gnu)
	type="lo"
        ;;
    i386-unknown-freebsdelf3.4)
    i386-unknown-netbsd1.4.2)
	type="alias"
	;;
esac

for ns in 1 2 3 4
do
	case "$type" in
	    lo0)
		ifconfig lo0:$ns 10.53.0.$ns up
		;;
	    lo)
		ifconfig lo:$ns 10.50.0.$ns up
		;;
	    alias)
		ifconfig lo0 10.50.0.$ns alias
		;;
            *)
		echo "Don't know how to set up interface.  Giving up."
		exit 1
	esac

done
