<!--
For potential security problems (e.g., repeatable assertions or crashes in `named`),
use Security_issue template instead!

BIND 9 threat model https://bind9.readthedocs.io/en/latest/chapter7.html#threat-model
defines what constitutes a security issue.
-->

<!--
Provide ONLY the information requested by this template, with the minimum
detail needed to reproduce and assess the issue.
No code flow explanation, no affected version ranges, no history of code changes,
no CVSS scoring, etc. Our team handles all that.

Fake reports result in an immediate ban.
-->

### Summary

<!-- Summarize the bug, preferably in one paragraph or less. -->

### BIND version affected
<!--
Test the **latest** supported BIND version for your branch to rule out fixed bugs.

Supported versions: https://kb.isc.org/docs/supported-platforms
Latest source: https://www.isc.org/download/#BIND

Paste `named -V` output.
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

### What is the current *bug* behavior?

<!-- What actually happens. -->

### What is the expected *correct* behavior?

<!-- What you should see instead. -->

### Relevant logs

<!-- Paste relevant logs, console output, and code in code blocks (```). -->

/label ~Bug
