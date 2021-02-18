<!--
THIS ISSUE TEMPLATE IS INTENDED ONLY FOR INTERNAL USE.

If the bug you are reporting is potentially security-related - for example,
if it involves an assertion failure or other crash in `named` that can be
triggered repeatedly - then please do *NOT* report it here, but send an
email to [security-officer@isc.org](security-officer@isc.org).
-->

### CVE-specific actions

  - [ ] Assign a CVE identifier
  - [ ] Determine CVSS score
  - [ ] Determine the range of BIND versions affected (including the Subscription Edition)
  - [ ] Determine whether workarounds for the problem exists
  - [ ] Prepare a detailed description of the problem which should include the following by default:
      - instructions for reproducing the problem (a system test is good enough)
      - explanation of code flow which triggers the problem (a system test is *not* good enough)
  - [ ] Prepare a private merge request containing the following items in separate commits:
      - a test for the issue (may be moved to a separate merge request for deferred merging)
      - a fix for the issue
      - documentation updates (`CHANGES`, release notes, anything else applicable)
  - [ ] Ensure the merge request from the previous step is reviewed by SWENG staff and has no outstanding discussions
  - [ ] Ensure the documentation changes introduced by the merge request addressing the problem are reviewed by Support and Marketing staff
  - [ ] Prepare backports of the merge request addressing the problem for all affected (and still maintained) BIND branches (backporting might affect the issue's scope and/or description)
  - [ ] Prepare a standalone patch for the last stable release of each affected (and still maintained) BIND branch

### Release-specific actions

  - [ ] Create/update the private issue containing links to fixes & reproducers for all CVEs fixed in a given release cycle
  - [ ] Reserve a block of `CHANGES` placeholders once the complete set of vulnerabilities fixed in a given release cycle is determined
  - [ ] Ensure the merge requests containing CVE fixes are merged into `security-*` branches in CVE identifier order
