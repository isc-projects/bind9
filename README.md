<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->
# BIND 9

### Contents

1. [Introduction](#intro)
1. [Reporting bugs and getting help](#help)
1. [Contributing to BIND](#contrib)
1. [Building BIND](#build)
1. [Automated testing](#testing)
1. [Documentation](#doc)
1. [Acknowledgments](#ack)

### <a name="intro"/> Introduction

BIND (Berkeley Internet Name Domain) is a complete, highly portable
implementation of the Domain Name System (DNS) protocol.

The BIND name server, `named`, can act as an authoritative name
server, recursive resolver, DNS forwarder, or all three simultaneously. It
implements views for split-horizon DNS, automatic DNSSEC zone signing and
key management, catalog zones to facilitate provisioning of zone data
throughout a name server constellation, response policy zones (RPZ) to
protect clients from malicious data, response rate limiting (RRL) and
recursive query limits to reduce distributed denial of service attacks,
and many other advanced DNS features. BIND also includes a suite of
administrative tools, including the `dig` and `delv` DNS lookup tools,
`nsupdate` for dynamic DNS zone updates, `rndc` for remote name server
administration, and more.

BIND 9 began as a complete rewrite of the BIND architecture that was
used in versions 4 and 8.  Internet Systems Consortium
([https://www.isc.org](https://www.isc.org)), a 501(c)(3) US public benefit
corporation dedicated to providing software and services in support of the
Internet infrastructure, developed BIND 9 and is responsible for its
ongoing maintenance and improvement. BIND is open source software
licensed under the terms of the Mozilla Public License, version 2.0.

For a detailed list of changes made throughout the history of BIND 9, see
the [changelog](doc/arm/changelog.rst).

For up-to-date versions and release notes, see
[https://www.isc.org/download/](https://www.isc.org/download/).

For information about supported platforms, see the
["Supported Platforms"](doc/arm/platforms.rst) section in the BIND 9
Administrator Reference Manual.

### <a name="help"/> Reporting bugs and getting help

To report non-security-sensitive bugs or request new features, you may
open an issue in the BIND 9 project on the
[ISC GitLab server](https://gitlab.isc.org) at
[https://gitlab.isc.org/isc-projects/bind9](https://gitlab.isc.org/isc-projects/bind9).

Please note that, unless you explicitly mark the newly created issue as
"confidential," it will be publicly readable. Please do not include any
information in bug reports that you consider to be confidential unless
the issue has been marked as such. In particular, if submitting the
contents of your configuration file in a non-confidential issue, it is
advisable to obscure key secrets; this can be done automatically by
using `named-checkconf -px`.

For information about ISC's Security Vulnerability Disclosure Policy and
information about reporting potential security issues, please see
`SECURITY.md`.

Professional support and training for BIND are available from
ISC. Contact us at [https://www.isc.org/contact](https://www.isc.org/contact)
for more information.

To join the __BIND Users__ mailing list, or view the archives, visit
[https://lists.isc.org/mailman/listinfo/bind-users](https://lists.isc.org/mailman/listinfo/bind-users).

If you're planning on making changes to the BIND 9 source code, you
may also want to join the __BIND Workers__ mailing list, at
[https://lists.isc.org/mailman/listinfo/bind-workers](https://lists.isc.org/mailman/listinfo/bind-workers).

### <a name="contrib"/> Contributing to BIND

ISC maintains a public git repository for BIND; details can be found
at [https://www.isc.org/sourceaccess/](https://www.isc.org/sourceaccess/).

Information for BIND contributors can be found in the following files:
- General information: [CONTRIBUTING.md](CONTRIBUTING.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- BIND 9 code style: [doc/dev/style.md](doc/dev/style.md)
- BIND architecture and developer guide: [doc/dev/dev.md](doc/dev/dev.md)

Patches for BIND may be submitted as
[merge requests](https://gitlab.isc.org/isc-projects/bind9/merge_requests)
on the [ISC GitLab server](https://gitlab.isc.org).

By default, external contributors do not have the ability to fork BIND on the
GitLab server; if you wish to contribute code to BIND, you may request
permission to do so. Thereafter, you can create git branches and directly
submit requests that they be reviewed and merged.

If you prefer, you may also submit code by opening a
[GitLab issue](https://gitlab.isc.org/isc-projects/bind9/issues) and
including your patch as an attachment, preferably generated by
`git format-patch`.

### <a name="build"/> Building BIND 9

For information about building BIND 9, see the
["Building BIND 9"](doc/arm/build.inc.rst) section in the BIND 9
Administrator Reference Manual.

### <a name="testing"/> Automated testing

A system test suite can be run with `pytest bin/tests/system`. The system
tests require you to configure a set of virtual IP addresses on your system
(this allows multiple servers to run locally and communicate with each other).
These IP addresses can be configured by running the command
`bin/tests/system/ifconfig.sh up` as root.

Some tests require Perl and the `Net::DNS` and/or `IO::Socket::IP` modules,
and are skipped if these are not available. Some tests require Python
and the `dnspython` module and are skipped if these are not available.
See bin/tests/system/README for further details.

Unit tests are implemented using the CMocka unit testing framework. To build
them, use the option `-Dcmocka=enabled`. Execution of unit tests is done by the
meson's test functionality; run by `meson test`.

### <a name="doc"/> Documentation

The *BIND 9 Administrator Reference Manual* (ARM) is included with the source
distribution, and in .rst format, in the `doc/arm`
directory. The HTML version is automatically generated and can
be viewed at [https://bind9.readthedocs.io/en/latest/index.html](https://bind9.readthedocs.io/en/latest/index.html).

The PDF version can be built by running:

    meson setup build
    ninja -C build arm-pdf

The above requires TeX Live in order to work. The PDF will be written to
`build/arm-pdf/latex/Bv9ARM.pdf`.

Man pages for some of the programs in the BIND 9 distribution
are also included in the BIND ARM.

Frequently (and not-so-frequently) asked questions and their answers
can be found in the ISC Knowledgebase at
[https://kb.isc.org](https://kb.isc.org).

Additional information on various subjects can be found in other
`README` files throughout the source tree.

#### Bug report identifiers

Most notes in the ARM Changelog appendix include a reference to a bug report or
issue number. Prior to 2018, these were usually of the form `[RT #NNN]`
and referred to entries in the "bind9-bugs" RT database, which was not open
to the public. More recent entries use the form `[GL #NNN]` or, less often,
`[GL !NNN]`, which, respectively, refer to issues or merge requests in the
GitLab database. Most of these are publicly readable, unless they include
information which is confidential or security-sensitive.

To look up a GitLab issue by its number, use the URL
[https://gitlab.isc.org/isc-projects/bind9/issues/NNN](https://gitlab.isc.org/isc-projects/bind9/issues).
To look up a merge request, use
[https://gitlab.isc.org/isc-projects/bind9/merge_requests/NNN](https://gitlab.isc.org/isc-projects/bind9/merge_requests).

In rare cases, an issue or merge request number may be followed with the
letter "P". This indicates that the information is in the private ISC
GitLab instance, which is not visible to the public.

### <a name="ack"/> Acknowledgments

* The original development of BIND 9 was underwritten by the
  following organizations:

		Sun Microsystems, Inc.
		Hewlett Packard
		Compaq Computer Corporation
		IBM
		Process Software Corporation
		Silicon Graphics, Inc.
		Network Associates, Inc.
		U.S. Defense Information Systems Agency
		USENIX Association
		Stichting NLnet - NLnet Foundation
		Nominum, Inc.

* This product includes software developed by the OpenSSL Project for use
  in the OpenSSL Toolkit.
  [https://www.OpenSSL.org/](https://www.OpenSSL.org/)
* This product includes cryptographic software written by Eric Young
  (eay@cryptsoft.com).
* This product includes software written by Tim Hudson (tjh@cryptsoft.com).
