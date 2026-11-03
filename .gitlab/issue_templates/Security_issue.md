<!--
Provide ONLY the information requested by this template, with the minimum
detail needed to reproduce and assess the issue.
No code flow explanation, no affected version ranges, no history of code changes,
no CVSS scoring, etc. Our team handles all that.

Security reports receive priority.
Fake reports waste resources and delay other project work, and result in an
immediate ban.
-->

### Summary
<!--
Summarize the bug, preferably in one paragraph or less.
-->

### BIND versions affected
<!--
Test the **latest** supported BIND version.
Supported versions: https://kb.isc.org/docs/supported-platforms
Latest source: https://www.isc.org/download/#BIND

Paste `named -V` output.
-->

### Preconditions and assumptions
<!--
Check the Threat Model:
https://bind9.readthedocs.io/en/latest/chapter7.html#threat-model

Is a specific setup needed?

Examples:
- DNSSEC validation disabled.
- Resolver forwards to attacker's server via DNS-over-TLS.
- Authoritative server transfers a specific primary zone.
- Attacker holds a key authorized to modify a zone.
- Attacker can shift the BIND server's clock, e.g., via NTP.
-->

### Attacker's abilities
<!--
What resources must the attacker control?

For authoritative servers, is a prior relationship required? E.g., the target
must transfer a malicious zone from the attacker's authoritative server via TLS.

For resolvers, must the attacker send arbitrary queries? Must they _also_
control an authoritative server?
-->


### Impact
<!--
Who or what is affected, and how?

Does a third party receive many packets from a reflection attack?

For attacks on BIND itself, quantify the impact on legitimate clients.
E.g., legitimate answers per second drop to 1/1000 within the first attack minute.

Compare the impact with the Threat Model baselines over the same transport.
-->


### Relevant configuration files

<!--
Paste relevant configuration files in code blocks (```).
Attach as files if large.

Hide secrets with `named-checkconf -px`.
-->

### Steps to reproduce
<!--
Give precise, minimal, itemized steps.
Provide a reproducer against a released version; source analysis alone is insufficient.

Minimize the reproducer. Use named instances on one machine instead of multiple
containers whenever possible. Use 10.53.0.x IP addresses configured by
bin/tests/system/ifconfig.sh as needed.

Include the full configuration files tested.

Example:
1. Use the attached configuration.
2. Start BIND: `named -g -c named.conf ...`
3. Simulate legitimate clients: `dnsperf -S1 -d legit-queries ...`
4. Simulate attack traffic: `dnsperf -S1 -d attack-queries ...`
-->

1.
2.
3.

### Actual insecure behavior

<!--
Examples:
Legitimate QPS drops 1000x.
Unbounded memory growth crashes the server.
The server crashes immediately.
-->

### Expected secure behavior

<!--
Optional. Leave empty if unsure.

For resource exhaustion, how should BIND behave? Refuse further requests?

What heuristic could distinguish legitimate and attack traffic?
-->

### Relevant logs
<!--
Include full named logs and test tool output (e.g., dnsperf, DNS Shotgun, kxdpgun).

Use matching timestamps across log files so events can be correlated.

For resource exhaustion, _also_ include system monitoring data, e.g., from
https://gitlab.isc.org/isc-projects/resource-monitor/.
-->

### Coordination
- Does this issue affect multiple implementations?
<!--
Issues affecting multiple implementations require very careful coordination. We
have to make sure the information does not leak to the public until vendors are ready to
release fixed versions. If it is a multi-vendor issue, we need to know about the situation
as soon as possible to start the (confidential!) coordination process within
DNS-OARC and other suitable fora.

List implementations tested.
-->

- Have you shared the information with anyone else?
<!--
E.g., informed affected vendors or submitted a paper for review?
-->

- What is your plan to publicize this issue?
<!--
E.g., disclose at conference XYZ on 20XX-XX-XX.
-->

### Acknowledgements
<!--
Specify whether and how to credit you publicly for discovering the issue.
Usual format:
First_name Last_name, Company_or_Team.
-->

<!-- DO NOT modify the following two lines. -->

/label ~Bug ~Security
/confidential
