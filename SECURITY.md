<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->
# Security Policy

ISC's Security Vulnerability Disclosure Policy is documented in the
relevant [ISC Knowledgebase article][1].

## Reporting possible security issues

If you think you may be seeing a potential security vulnerability in BIND (for
example, a crash with a REQUIRE, INSIST, or ASSERT failure), please report it
immediately by [opening a confidential GitLab issue][2]. If a GitLab issue is
not an option, please use the template from the file
.gitlab/issue_templates/Security_issue.mde-mail and send it to
bind-security@isc.org.

Please do not discuss undisclosed security vulnerabilities on any public
mailing list. ISC has a long history of handling reported
vulnerabilities promptly and effectively and we respect and acknowledge
responsible reporters.

If you have a crash, you may want to consult the Knowledgebase article
entitled ["What to do if your BIND or DHCP server has crashed"][3].

## Reporting bugs

We are working with the interests of the greater Internet at heart, and
we hope you are too. In that vein, we do not offer bug bounties. If you
think you have found a bug in any ISC software, we encourage you to
[report it responsibly][2]; if verified, we will be happy to credit you
in our Release Notes.

[1]: https://kb.isc.org/docs/aa-00861
[2]: https://gitlab.isc.org/isc-projects/bind9/-/issues/new?issue[confidential]=true&issuable_template=Security_issue
[3]: https://kb.isc.org/docs/aa-00340
