<!--
If the bug you are reporting is potentially security-related - for example,
if it involves an assertion failure or other crash in `named` that can be
triggered repeatedly - then please make sure that you make the new issue
confidential by clicking the checkbox at the bottom!
-->

### Summary

<!-- Concisely summarize the bug encountered. -->

### BIND version affected
<!--
Make sure you are testing with the **latest** supported version of BIND
for a given branch. Many bugs have been fixed over time!

See https://kb.isc.org/docs/supported-platforms for the current list.
The latest source is available from https://www.isc.org/download/#BIND

Paste the output of `named -V` here.
-->

### Steps to reproduce

<!--
This is extremely important! Be precise and use itemized lists, please.

Even if a default configuration is affected, please include the full configuration
files _you were testing with_.

Example:
1. Use _attached_ configuration file
2. Start BIND server with command: `named -g -c named.conf ...`
3. Simulate legitimate clients using command `dnsperf -S1 -d legit-queries ...`
4. Simulate attack traffic using command `dnsperf -S1 -d attack-queries ...`
-->

1.
2.
3.

### What is the current *bug* behavior?

<!-- What actually happens. -->

### What is the expected *correct* behavior?

<!-- What you should see instead. -->

### Relevant configuration files

<!-- Paste any relevant configuration files here - please use code blocks (```)
to format console output. If submitting the contents of your
configuration file in a non-confidential issue, it is advisable to
obscure key secrets; this can be done automatically by using
`named-checkconf -px`. -->

### Relevant logs

<!-- Paste any relevant logs here - please use code blocks (```) to format console
output, logs, and code, as it's very hard to read otherwise. -->

/label ~Bug
