#!/usr/bin/perl
#
# Ad hoc name server
#

use IO::File;
use IO::Socket;
use Net::DNS;
use Net::DNS::Packet;

my $sock = IO::Socket::INET->new(LocalAddr => "10.53.0.3", 
   LocalPort => 5300, Proto => "udp") or die "$!";

my $pidf = new IO::File "ans.pid", "w" or die "cannot write pid file: $!";
print $pidf "$$\n";
$pidf->close;
sub rmpid { unlink "ans.pid"; exit 1; };

$SIG{INT} = \&rmpid;
$SIG{TERM} = \&rmpid;

for (;;) {
	$sock->recv($buf, 512);

	print "**** request from " , $sock->peerhost, " port ", $sock->peerport, "\n";

	my ($packet, $err) = new Net::DNS::Packet(\$buf, 0);
	$err and die $err;

	print "REQUEST:\n";	
	$packet->print;

	$packet->header->qr(1);

	$packet->push("answer", new Net::DNS::RR("www.example.com 300 A 1.2.3.4"));
	
	$sock->send($packet->data);

	print "RESPONSE:\n";
	$packet->print;
	print "\n";	
}
