#!/bin/sh
#
# Set up interface aliases for bind9 system tests.
#

sys=`../../../config.guess`

case "$1" in

    'start')
	for ns in 1 2 3 4
	do
		case "$sys" in 
		    sparc-sun-solaris2.[6-8])
			ifconfig lo0:$ns 10.53.0.$ns up
			;;
		    *-pc-linux-gnu)
			ifconfig lo:$ns 10.53.0.$ns up
		        ;;
		    *-unknown-freebsdelf3.4)
			ifconfig lo0 10.53.0.$ns alias
			;;
		    *-unknown-netbsd*)
			ifconfig lo0 10.53.0.$ns alias
			;;
		    *-pc-bsdi3.*)
			ifconfig lo0 add 10.53.0.$ns
			;;
		    *-dec-osf5.*)
			ifconfig lo0 alias 10.53.0.$ns
			;;
		    *-dec-osf4.*)
			ifconfig lo0 alias 10.53.0.$ns
			;;
		    *-pc-bsdi4.*)
			ifconfig lo0 add 10.53.0.$ns
			;;
	            *)
			echo "Don't know how to set up interface.  Giving up."
			exit 1
		esac
	done
	;;

    'stop')
	for ns in 4 3 2 1
	do
		case "$sys" in 
		    sparc-sun-solaris2.[6-8])
			ifconfig lo0:$ns 10.53.0.$ns down
			;;
		    *-pc-linux-gnu)
			ifconfig lo:$ns 10.53.0.$ns down
		        ;;
		    *-unknown-freebsdelf3.4)
			ifconfig lo0 10.53.0.$ns delete
			;;
		    *-unknown-netbsd*)
			ifconfig lo0 10.53.0.$ns delete
			;;
		    *-pc-bsdi3.*)
			ifconfig lo0 remove 10.53.0.$ns
			;;
		    *-dec-osf5.*)
			ifconfig lo0 -alias 10.53.0.$ns
			;;
		    *-dec-osf4.*)
			ifconfig lo0 -alias 10.53.0.$ns
			;;
		    *-pc-bsdi4.*)
			ifconfig lo0 remove 10.53.0.$ns
			;;
	            *)
			echo "Don't know how to destroy interface.  Giving up."
			exit 1
		esac
	done
	;;
esac
