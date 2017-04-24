<!---
 - Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
 -
 - Permission to use, copy, modify, and/or distribute this software for any
 - purpose with or without fee is hereby granted, provided that the above
 - copyright notice and this permission notice appear in all copies.
 -
 - THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 - REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 - AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 - INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 - LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 - OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 - PERFORMANCE OF THIS SOFTWARE.
--->
## BIND Source Access and Contributor Guidelines
*Apr 14, 2017*

### Contents

1. [Access to source code](#access)
1. [Reporting bugs](#bugs)
1. [Contributing code](#contrib)

### Introduction

Thank you for using BIND!

BIND is open source software that implements the Domain Name System (DNS)
protocols for the Internet. It is a reference implementation of those
protocols, but it is also production-grade software, suitable for use in
high-volume and high-reliability applications.  It is by far the most
widely used DNS software, providing a robust and stable platform on top of
which organizations can build distributed computing systems with the
knowledge that those systems are fully compliant with published DNS
standards.

BIND is and will always remain free and openly available.  It can be
used and modified in any way by anyone.

BIND is maintained by the [Internet Systems Consortium](https://www.isc.org),
a public-benefit 501(c)(3) nonprofit, using a "managed open source" approach:
anyone can see the source, but only ISC employees have commit access.
Until recently, the source could only be seen once ISC had published
a release: read access to the source repository was restricted just
as commit access was.  That's now changing, with the opening of a
public git mirror to the BIND source tree (see below).

### <a name="access"></a>Access to source code

Public BIND releases are always available from the
[ISC FTP site](ftp://ftp.isc.org/isc/bind9).

A public-access GIT repository is also available at
[https://bindmember.isc.org](https://bindmember.isc.org).
This repository is a mirror, updated several times per day, of the
source repository maintained by ISC.  It contains all the public release
branches; upcoming releases can be viewed in their current state at any
time.  It does *not* contain development branches or unreviewed work in
progress.  Commits which address security vulnerablilities are withheld
until after public disclosure.

You can browse the source online via
[https://bindmember.isc.org/cgi-bin/gitweb.cgi?p=bind9.git;a=summary](https://bindmember.isc.org/cgi-bin/gitweb.cgi?p=bind9.git;a=summary)

To clone the repository, use:

>       $ git clone https://bindmember.isc.org/git/bind9.git

Branch names are of the form `v9_X`, where X represents the second number in the BIND 9 version number.  So, to check out the BIND 9.10 branch, use:

>       $ git checkout v9_10

Whenever a branch is ready for publication, a tag will be placed of the
form `v9_X_Y`.  The 9.9.5 release, for instance, is tagged as `v9_9_5`.

The branch in which the next major release is being developed is called
`master`.

### <a name="bugs"></a>Reporting bugs

Reports of flaws in the BIND package, including software bugs, errors in
the documentation, missing files in the tarball, etc, can be emailed to
`bind9-bugs@isc.org`, or reported via the
[bug submission form](http://www.isc.org/community/report-bug) at
[http://www.isc.org/community/report-bug](http://www.isc.org/community/report-bug).

Suggested changes or requests for new features can be emailed to
`bind-suggest@isc.org`.  Both bugs and suggestions are stored in the
ticketing system used by the software engineering team at ISC.

All submissions to the ticketing system receive an automatic response.  Any
followup email sent to the ticketing system should use the same subject
header, so that it will be routed to the same ticket.

Due to a large ticket backlog and an even larger quantity of incoming spam,
we are sometimes slow to respond, especially if a bug is cosmetic or if a
feature request is vague or low in priority, but we will try at least to
acknowledge legitimate bug reports within a week.

Currently, ISC's ticketing system is not publicly readable. However, ISC
may open it in the future. Please do not include information you consider
to be confidential.

### <a name="bugs"></a>Contributing code

BIND's [open source
license](http://www.isc.org/downloads/software-support-policy/isc-license/)
not require changes to be contributed back to ISC, but this page
includes some guidelines for those who would like to do so.

We accept two different types of code contribution:  Code intended for
inclusion in [BIND](#bind) itself, and code intended for the
[`contrib`](#contrib) directory.

#### <a name="bind"></a>BIND code

Patches for BIND itself may be submitted using the same methods as bug
reports or suggestions.  When submitting a patch, please prepend the
subject header with "`[PATCH]`" so it will be easier for us to find.  If
your patch introduces a new feature in BIND, please submit it to
`bind-suggest@isc.org`; if it fixes a bug, please submit it to
`bind9-bugs@isc.org`.

ISC does not require an explicit copyright assignment for patch
contributions.  However, by submitting a patch to ISC, you implicitly
certify that you are the author of the code, that you intend to reliquish
exclusive copyright, and that you grant permission to publish your work
under the
[Mozilla Public License 2.0](http://www.isc.org/downloads/software-support-policy/isc-license/)
for BIND 9.11 and higher, and the
[ISC License](http://www.isc.org/downloads/software-support-policy/isc-license/)
for BIND 9.10 and earlier.

Patches should be submitted as diffs against a specific version of BIND --
preferably the current top of the `master` branch.  Diffs may be
generated using either `git format-patch` or `git diff`.

Those wanting to write code for BIND may be interested in the [developer
information](dev.md) page, which includes information about BIND design and
coding practices, including discussion of internal APIs and overall system
architecture.  (This is a work in progress, and still quite preliminary.)

Every patch submitted will be reviewed by ISC engineers following our [code
review process](dev.md#reviews) before it is merged.

It may take considerable time to review patch submissions, especially if
they don't meet ISC style and quality guidelines.  If the patch is a good
idea, we can and will do additional work to bring them up to par, but if
we're busy with other work, it may take us a long time to get to it.

To ensure your patch is acted on as promptly as possible, please:

* Try to adhere to the [BIND 9 coding style](style.md).
* Run `make` `check` to ensure your change hasn't caused any
  functional regressions.
* Document your work, both in the patch itself and in the
  accompanying email.
* In patches that make non-trivial functional changes, include system
  tests if possible; when introducing or substantially altering a
  library API, include unit tests. See [Testing](dev.md#testing)
  for more information.

##### Changes to `configure`

If you need to make changes to `configure`, you should not edit it
directly; instead, edit `configure.in`, then run `autoconf`.  Similarly,
instead of editing `config.h.in` directly, edit `configure.in` and run
`autoheader`.

When submitting your patch, it is fine to omit the `configure` diffs.
Just send the `configure.in` diffs and we'll generate the new `configure`
during the review process.

##### Documentation

All functional changes should be documented. There are three types
of documentation in the BIND source tree:

* Man pages are kept alongside the source code for the commands
  they document, in files ending in `.docbook`; for example, the
  `named` man page is `bin/named/named.docbook`.
* The *BIND 9 Administrator Reference Manual* is mostly in
  `doc/arm/Bv9ARM-book.xml`, plus a few other XML files that are included
  in it.
* API documentation is in the header file describing the API, in
  Doxygen-formatted comments.

It is not necessary to edit any documentation files other than these; the
PDF, HTML, and `nroff`-format files will be generated automatically
from the `docbook` and `XML` files by a script whenever a documentation
change is merged to a release branch.

#### <a name="contrib"></a>Contrib code

The software in the `contrib` directory of the BIND 9 `tar` archive is not
formally supported by ISC, but is included for the convenience of users.
These are things we consider useful or informative, but are not able to
support at the same level as BIND.

`contrib` includes some useful DNS-related open source tools such as `zkt`,
`nslint`, and the `idnkit` library for internationalized domain name
support; useful scripts such as `nanny.pl` and `mkdane.sh`; performance
testers including `queryperf` and `perftcpdns`; and drivers and modules for
DLZ.

If you have code with a BSD-compatible license that you would like us to
include in `contrib`, please send it to `bind-suggest@isc.org`, with
"`[CONTRIB]`" in the subject header.
