.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

..
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.

   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

.. General:

General DNS Reference Information
=================================

.. _ipv6addresses:

IPv6 addresses (AAAA)
---------------------

IPv6 addresses are 128-bit identifiers for interfaces and sets of
interfaces which were introduced in the DNS to facilitate scalable
Internet routing. There are three types of addresses: *Unicast*, an
identifier for a single interface; *Anycast*, an identifier for a set of
interfaces; and *Multicast*, an identifier for a set of interfaces. Here
we describe the global Unicast address scheme. For more information, see
:rfc:`3587`, "Global Unicast Address Format."

IPv6 unicast addresses consist of a *global routing prefix*, a *subnet
identifier*, and an *interface identifier*.

The global routing prefix is provided by the upstream provider or ISP,
and (roughly) corresponds to the IPv4 *network* section of the address
range. The subnet identifier is for local subnetting, much the same as
subnetting an IPv4 /16 network into /24 subnets. The interface
identifier is the address of an individual interface on a given network;
in IPv6, addresses belong to interfaces rather than to machines.

The subnetting capability of IPv6 is much more flexible than that of
IPv4: subnetting can be carried out on bit boundaries, in much the same
way as Classless InterDomain Routing (CIDR), and the DNS PTR
representation ("nibble" format) makes setting up reverse zones easier.

The Interface Identifier must be unique on the local link, and is
usually generated automatically by the IPv6 implementation, although it
is usually possible to override the default setting if necessary. A
typical IPv6 address might look like:
``2001:db8:201:9:a00:20ff:fe81:2b32``

IPv6 address specifications often contain long strings of zeros, so the
architects have included a shorthand for specifying them. The double
colon (``::``) indicates the longest possible string of zeros that can
fit, and can be used only once in an address.

.. _bibliography:

Bibliography (and Suggested Reading)
------------------------------------

.. _rfcs:

Request for Comments (RFCs)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Specification documents for the Internet protocol suite, including the
DNS, are published as part of the Request for Comments (RFCs) series of
technical notes. The standards themselves are defined by the Internet
Engineering Task Force (IETF) and the Internet Engineering Steering
Group (IESG). RFCs can be obtained online via FTP at:

`ftp://www.isi.edu/in-notes/RFCxxxx.txt <ftp://www.isi.edu/in-notes/>`__

(where xxxx is the number of the RFC). RFCs are also available via the
Web at:

http://www.ietf.org/rfc/.

Standards
---------

:rfc:`974` - C. Partridge. *Mail Routing and the Domain System.* January 1986.

:rfc:`1034` - P.V. Mockapetris. *Domain Names — Concepts and Facilities.* November
1987.

:rfc:`1035` - P. V. Mockapetris. *Domain Names — Implementation and Specification.*
November 1987.

.. _proposed_standards:

Proposed Standards
------------------

:rfc:`2181` - R. Elz and R. Bush. *Clarifications to the DNS Specification.* July 1997.

:rfc:`2308` - M. Andrews. *Negative Caching of DNS Queries.* March 1998.

:rfc:`1995` - M. Ohta. *Incremental Zone Transfer in DNS.* August 1996.

:rfc:`1996` - P. Vixie. *A Mechanism for Prompt Notification of Zone Changes.*
August 1996.

:rfc:`2136` - P. Vixie, S. Thomson, Y. Rekhter, and J. Bound. *Dynamic Updates in the
Domain Name System.* April 1997.

:rfc:`2671` - P. Vixie. *Extension Mechanisms for DNS (EDNS0).* August 1997.

:rfc:`2672` - M. Crawford. *Non-Terminal DNS Name Redirection.* August 1999.

:rfc:`2845` - P. Vixie, O. Gudmundsson, D. Eastlake, 3rd, and B. Wellington. *Secret Key
Transaction Authentication for DNS (TSIG).* May 2000.

:rfc:`2930` - D. Eastlake, 3rd. *Secret Key Establishment for DNS (TKEY RR).*
September 2000.

:rfc:`2931` - D. Eastlake, 3rd. *DNS Request and Transaction Signatures (SIG(0)s).*
September 2000.

:rfc:`3007` - B. Wellington. *Secure Domain Name System (DNS) Dynamic Update.*
November 2000.

:rfc:`3645` - S. Kwan, P. Garg, J. Gilroy, L. Esibov, J. Westhead, and R. Hall. *Generic
Security Service Algorithm for Secret Key Transaction Authentication for
DNS (GSS-TSIG).* October 2003.

DNS Security Proposed Standards
-------------------------------

:rfc:`3225` - D. Conrad. *Indicating Resolver Support of DNSSEC.* December 2001.

:rfc:`3833` - D. Atkins and R. Austein. *Threat Analysis of the Domain Name System
(DNS).* August 2004.

:rfc:`4033` - R. Arends, R. Austein, M. Larson, D. Massey, and S. Rose. *DNS Security
Introduction and Requirements.* March 2005.

:rfc:`4034` - R. Arends, R. Austein, M. Larson, D. Massey, and S. Rose. *Resource Records for
the DNS Security Extensions.* March 2005.

:rfc:`4035` - R. Arends, R. Austein, M. Larson, D. Massey, and S. Rose. *Protocol
Modifications for the DNS Security Extensions.* March 2005.

Other Important RFCs About DNS Implementation
---------------------------------------------

:rfc:`1535` - E. Gavron. *A Security Problem and Proposed Correction With Widely
Deployed DNS Software.* October 1993.

:rfc:`1536` - A. Kumar, J. Postel, C. Neuman, P. Danzig, and S. Miller. *Common DNS
Implementation Errors and Suggested Fixes.* October 1993.

:rfc:`1982` - R. Elz and R. Bush. *Serial Number Arithmetic.* August 1996.

:rfc:`4074` - Y. Morishita and T. Jinmei. *Common Misbehaviour Against DNS Queries for
IPv6 Addresses.* May 2005.

Resource Record Types
---------------------

:rfc:`1183` - C. F. Everhart, L. A. Mamakos, R. Ullmann, P. Mockapetris. *New DNS RR
Definitions.* October 1990.

:rfc:`1706` - B. Manning and R. Colella. *DNS NSAP Resource Records.* October 1994.

:rfc:`2168` - R. Daniel and M. Mealling. *Resolution of Uniform Resource Identifiers
using the Domain Name System.* June 1997.

:rfc:`1876` - C. Davis, P. Vixie, T. Goodwin, and I. Dickinson. *A Means for Expressing
Location Information in the Domain Name System.* January 1996.

:rfc:`2052` - A. Gulbrandsen and P. Vixie. *A DNS RR for Specifying the Location of
Services.* October 1996.

:rfc:`2163` - A. Allocchio. *Using the Internet DNS to Distribute MIXER
Conformant Global Address Mapping.* January 1998.

:rfc:`2230` - R. Atkinson. *Key Exchange Delegation Record for the DNS.* October
1997.

:rfc:`2536` - D. Eastlake, 3rd. *DSA KEYs and SIGs in the Domain Name System (DNS).*
March 1999.

:rfc:`2537` - D. Eastlake, 3rd. *RSA/MD5 KEYs and SIGs in the Domain Name System
(DNS).* March 1999.

:rfc:`2538` - D. Eastlake, 3rd and O. Gudmundsson. *Storing Certificates in the Domain
Name System (DNS).* March 1999.

:rfc:`2539` - D. Eastlake, 3rd. *Storage of Diffie-Hellman Keys in the Domain Name
System (DNS).* March 1999.

:rfc:`2540` - D. Eastlake, 3rd. *Detached Domain Name System (DNS) Information.*
March 1999.

:rfc:`2782` - A. Gulbrandsen, P. Vixie, and L. Esibov. *A DNS RR for specifying the
location of services (DNS SRV).* February 2000.

:rfc:`2915` - M. Mealling and R. Daniel. *The Naming Authority Pointer (NAPTR) DNS
Resource Record.* September 2000.

:rfc:`3110` - D. Eastlake, 3rd. *RSA/SHA-1 SIGs and RSA KEYs in the Domain Name
System (DNS).* May 2001.

:rfc:`3123` - P. Koch. *A DNS RR Type for Lists of Address Prefixes (APL RR).* June
2001.

:rfc:`3596` - S. Thomson, C. Huitema, V. Ksinant, and M. Souissi. *DNS Extensions to
support IP version 6.* October 2003.

:rfc:`3597` - A. Gustafsson. *Handling of Unknown DNS Resource Record (RR) Types.*
September 2003.

DNS and the Internet
--------------------

:rfc:`1101` - P. V. Mockapetris. *DNS Encoding of Network Names and Other Types.*
April 1989.

:rfc:`1123` - R. Braden. *Requirements for Internet Hosts - Application and
Support.* October 1989.

:rfc:`1591` - J. Postel. *Domain Name System Structure and Delegation.* March 1994.

:rfc:`2317` - H. Eidnes, G. de Groot, and P. Vixie. *Classless IN-ADDR.ARPA Delegation.*
March 1998.

:rfc:`2826` - Internet Architecture Board. *IAB Technical Comment on the Unique
DNS Root.* May 2000.

:rfc:`2929` - D. Eastlake, 3rd, E. Brunner-Williams, and B. Manning. *Domain Name System
(DNS) IANA Considerations.* September 2000.

DNS Operations
--------------

:rfc:`1033` - M. Lottor. *Domain administrators operations guide.* November 1987.

:rfc:`1537` - P. Beertema. *Common DNS Data File Configuration Errors.* October
1993.

:rfc:`1912` - D. Barr. *Common DNS Operational and Configuration Errors.* February
1996.

:rfc:`2010` - B. Manning and P.Vixie. *Operational Criteria for Root Name Servers.*
October 1996.

:rfc:`2219` - M. Hamilton and R. Wright. *Use of DNS Aliases for Network Services.*
October 1997.

Internationalized Domain Names
------------------------------

:rfc:`2825` - IAB and R. Daigle. *A Tangled Web: Issues of I18N, Domain Names, and
the Other Internet protocols.* May 2000.

:rfc:`3490` - P. Faltstrom, P. Hoffman, and A. Costello. *Internationalizing Domain Names
in Applications (IDNA).* March 2003.

:rfc:`3491` - P. Hoffman and M. Blanchet. *Nameprep: A Stringprep Profile for
Internationalized Domain Names.* March 2003.

:rfc:`3492` - A. Costello. *Punycode: A Bootstring encoding of Unicode for
Internationalized Domain Names in Applications (IDNA).* March 2003.

Other DNS-related RFCs
----------------------

.. note::

   Note: the following list of RFCs, although DNS-related, are not
   concerned with implementing software.

:rfc:`1464` - R. Rosenbaum. *Using the Domain Name System To Store Arbitrary
String Attributes.* May 1993.

:rfc:`1713` - A. Romao. *Tools for DNS Debugging.* November 1994.

:rfc:`1794` - T. Brisco. *DNS Support for Load Balancing.* April 1995.

:rfc:`2240` - O. Vaughan. *A Legal Basis for Domain Name Allocation.* November 1997.

:rfc:`2345` - J. Klensin, T. Wolf, and G. Oglesby. *Domain Names and Company Name
Retrieval.* May 1998.

:rfc:`2352` - O. Vaughan. *A Convention For Using Legal Names as Domain Names.* May
1998.

:rfc:`3071` - J. Klensin. *Reflections on the DNS, RFC 1591, and Categories of
Domains.* February 2001.

:rfc:`3258` - T. Hardie. *Distributing Authoritative Name Servers via Shared
Unicast Addresses.* April 2002.

:rfc:`3901` - A. Durand and J. Ihren. *DNS IPv6 Transport Operational Guidelines.*
September 2004.

Obsolete and Unimplemented Experimental RFC
-------------------------------------------

:rfc:`1712` - C. Farrell, M. Schulze, S. Pleitner, and D. Baldoni. *DNS Encoding of
Geographical Location.* November 1994.

:rfc:`2673` - M. Crawford. *Binary Labels in the Domain Name System.* August 1999.

:rfc:`2874` - M. Crawford and C. Huitema. *DNS Extensions to Support IPv6 Address
Aggregation and Renumbering.* July 2000.

Obsoleted DNS Security RFCs
---------------------------

.. note::

   Most of these have been consolidated into :rfc:`4033`, :rfc:`4034` and
   :rfc:`4035` which collectively describe DNSSECbis.

:rfc:`2065` - D. Eastlake, 3rd and C. Kaufman. *Domain Name System Security Extensions.*
January 1997.

:rfc:`2137` - D. Eastlake, 3rd. *Secure Domain Name System Dynamic Update.* April
1997.

:rfc:`2535` - D. Eastlake, 3rd. *Domain Name System Security Extensions.* March 1999.

:rfc:`3008` - B. Wellington. *Domain Name System Security (DNSSEC) Signing
Authority.* November 2000.

:rfc:`3090` - E. Lewis. *DNS Security Extension Clarification on Zone Status.*
March 2001.

:rfc:`3445` - D. Massey and S. Rose. *Limiting the Scope of the KEY Resource Record
(RR).* December 2002.

:rfc:`3655` - B. Wellington and O. Gudmundsson. *Redefinition of DNS Authenticated
Data (AD) bit.* November 2003.

:rfc:`3658` - O. Gudmundsson. *Delegation Signer (DS) Resource Record (RR).*
December 2003.

:rfc:`3755` - S. Weiler. *Legacy Resolver Compatibility for Delegation Signer
(DS).* May 2004.

:rfc:`3757` - O. Kolkman, J. Schlyter, and E. Lewis. *Domain Name System KEY (DNSKEY)
Resource Record (RR) Secure Entry Point (SEP) Flag.* April 2004.

:rfc:`3845` - J. Schlyter. *DNS Security (DNSSEC) NextSECure (NSEC) RDATA Format.*
August 2004.

.. _internet_drafts:

Internet Drafts
~~~~~~~~~~~~~~~

Internet Drafts (IDs) are rough-draft working documents of the Internet
Engineering Task Force. They are, in essence, RFCs in the preliminary
stages of development. Implementors are cautioned not to regard IDs as
archival, and they should not be quoted or cited in any formal documents
unless accompanied by the disclaimer that they are "works in progress."
IDs have a lifespan of six months after which they are deleted unless
updated by their authors.

.. _more_about_bind:

Other Documents About BIND
~~~~~~~~~~~~~~~~~~~~~~~~~~

Paul Albitz and Cricket Liu. *DNS and BIND.* Copyright 1998 Sebastopol, CA: O'Reilly and
Associates.
