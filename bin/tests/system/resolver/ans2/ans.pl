#!/usr/bin/perl
#
# Ad hoc name server
#

use IO::File;
use IO::Socket;
use Net::DNS;
use Net::DNS::Packet;

my $sock = IO::Socket::INET->new(LocalAddr => "10.53.0.2",
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

	my @questions = $packet->question;
	my $qname = $questions[0]->qname;

	if ($qname eq "cname1.example.com") {
		# Data for the "cname + other data / 1" test
		$packet->push("answer", new Net::DNS::RR("cname1.example.com 300 CNAME cname1.example.com"));
		$packet->push("answer", new Net::DNS::RR("cname1.example.com 300 A 1.2.3.4"));
	} elsif ($qname eq "cname2.example.com") {
		# Data for the "cname + other data / 2" test: same RRs in opposite order
		$packet->push("answer", new Net::DNS::RR("cname2.example.com 300 A 1.2.3.4"));
		$packet->push("answer", new Net::DNS::RR("cname2.example.com 300 CNAME cname2.example.com"));
	} else {
		# Data for the "bogus referrals" test
		$packet->push("authority", new Net::DNS::RR("below.www.example.com 300 NS ns.below.www.example.com"));
		$packet->push("additional", new Net::DNS::RR("ns.below.www.example.com 300 A 10.53.0.3"));
	}

	$sock->send($packet->data);

	print "RESPONSE:\n";
	$packet->print;
	print "\n";
}
