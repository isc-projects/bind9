Copyright (C) 2001  Internet Software Consortium.
See COPYRIGHT in the source root or http://isc.org/copyright.html for terms.

$Id: readme1st.txt,v 1.5 2001/07/31 00:03:20 gson Exp $

	Beta Release of BIND 9.2.0 for Window NT/2000

Date: 20-Jul-2001.

  This is a Beta Release of BIND 9.2.0 for Windows NT/2000. As such
it should not be installed on a production system or anywhere that is
considered critical for Internet access.  The release has not been
thoroughly tested.  While IPv6 addresses should work, there is no
support yet for a BIND server using an IPv6 stack. Only IPv4 stacks are
supported on the box running this version of BIND. IPv6 stacks will
be supported in a future release.
  
	Kit Installation Information

If you have previously installed BIND 8 or BIND 4 on the system that
you wish to install this kit, you MUST use the BIND 8 or BIND 4 installer
to uninstall the previous kit.  For BIND 8.2.x, you can use the
BINDInstall that comes with the BIND 8 kit to uninstall it. The BIND 9
installer will NOT uninstall the BIND 8 binaries.  That will be fixed
in a future release.

Unpack the kit into any convenient directory and run the BINDInstall
program.  This will install the named and associated programs
into the correct directories and set up the required registry
keys.

	Controlling BIND

Windows NT/2000 uses the same rndc program as is used on Unix
systems.  The rndc.conf file must be configured for your system in
order to work. You will need to generate a key for this. To do this
use the rndc-confgen program. The program will be installed in the
same directory as named: dns/bin/.  Use the command this way:

rndc-confgen > rndc.conf

An rndc.conf will be generated in the current directory but not copied to
the dns/etc directory where it needs to reside.

In addition the named.conf file will need to be modified in order
to allow rndc to control named. The additions look like the following:

key rndckey { algorithm hmac-md5; secret "xxxxxxxxx=="; };

controls {
	inet 127.0.0.1 allow { localhost; } keys { rndckey; };
};

Note that the value of the secret must come from the key generated
above for rndc and must be the same key value for both. If you
have rndc on a Unix box you can use it to control BIND on the NT/W2K
box as well as using the Windows version of rndc to control a BIND 9
daemon on a Unix box.

In addition BIND is installed as a win32 system service, can be
started and stopped in the same way as any other service and
automatically starts at whenever the system is booted.

	DNS Tools

I have built versions of the following tools for Windows NT: dig,
nslookup, host, nsupdate, named-checkconf, named-checkzone, dnssec-keygen,
dnssec-makekeyset, dnssec-signkey, dnssec-signzone. The tools will NOT run
on Win9x, only WinNT and Win2000. The latter tools are for use with DNSSEC.
All tools are installed in the dns/bin directory.

	Problems

Please report all problems to bind9-bugs@isc.org and not to me. All
other questions should go to the bind-users@isc.org mailing list and
news group.

	Danny Mayer
	danny.mayer@nominum.com

