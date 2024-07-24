<!--
THIS ISSUE TEMPLATE IS INTENDED ONLY FOR INTERNAL USE.

If the bug you are reporting is potentially security-related - for example,
if it involves an assertion failure or other crash in `named` that can be
triggered repeatedly - then please make sure that you make the new issue
confidential!
-->
| Quick Links              | :link:                               |
| ------------------------ | ------------------------------------ |
| Incident Manager:        | @user                                |
| Deputy Incident Manager: | @user                                |
| Public Disclosure Date:  | YYYY-MM-DD                           |
| CVSS Score:              | [0.0][cvss_score]                    |
| Security Advisory:       | isc-private/printing-press!NNN       |
| Mattermost Channel:      | [CVE-YYYY-NNNN][mattermost_url]      |
| Support Ticket:          | [URL]                                |
| Release Checklist:       | #NNNN                                |

[cvss_score]: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X&version=3.1
[mattermost_url]:

:bulb: **Click [here][checklist_explanations] (internal resource) for general information about the security incident handling process.**

[checklist_explanations]: https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations

### Earlier Than T-5

  - [ ] [:link:][step_deputy]            **(IM)** Pick a Deputy Incident Manager
  - [ ] [:link:][step_respond]           **(IM)** Respond to the bug reporter
  - [ ] [:link:][step_public_mrs]        **(SwEng)** Ensure there are no public merge requests which inadvertently disclose the issue
  - [ ] [:link:][step_assign_cve_id]     **(IM)** Assign a CVE identifier
  - [ ] [:link:][step_note_cve_info]     **(SwEng)** Update this issue with the assigned CVE identifier and the CVSS score
  - [ ] [:link:][step_versions_affected] **(SwEng)** Determine the range of product versions affected (including the Subscription Edition)
  - [ ] [:link:][step_workarounds]       **(SwEng)** Determine whether workarounds for the problem exist
  - [ ] [:link:][step_coordinate]        **(SwEng)** If necessary, coordinate with other parties
  - [ ] [:link:][step_earliest_prepare]  **(Support)** Prepare "earliest" notification text and hand it off to Marketing
  - [ ] [:link:][step_earliest_send]     **(Marketing)** Update "earliest" notification document in SF portal and send bulk email to earliest customers
  - [ ] [:link:][step_advisory_mr]       **(Support)** Create a merge request for the Security Advisory and include all readily available information in it
  - [ ] [:link:][step_reproducer_mr]     **(SwEng)** Prepare a private merge request containing a system test reproducing the problem
  - [ ] [:link:][step_notify_support]    **(SwEng)** Notify Support when a reproducer is ready
  - [ ] [:link:][step_code_analysis]     **(SwEng)** Prepare a detailed explanation of the code flow triggering the problem
  - [ ] [:link:][step_fix_mr]            **(SwEng)** Prepare a private merge request with the fix
  - [ ] [:link:][step_review_fix]        **(SwEng)** Ensure the merge request with the fix is reviewed and has no outstanding discussions
  - [ ] [:link:][step_review_docs]       **(Support)** Review the documentation changes introduced by the merge request with the fix
  - [ ] [:link:][step_backports]         **(SwEng)** Prepare backports of the merge request addressing the problem for all affected (and still maintained) branches of a given product
  - [ ] [:link:][step_finish_advisory]   **(Support)** Finish preparing the Security Advisory
  - [ ] [:link:][step_meta_issue]        **(QA)** Create (or update) the private issue containing links to fixes & reproducers for all CVEs fixed in a given release cycle
  - [ ] [:link:][step_merge_fixes]       **(QA)** Merge the CVE fixes in CVE identifier order
  - [ ] [:link:][step_patches]           **(QA)** Prepare a standalone patch for the last stable release of each affected (and still maintained) product branch
  - [ ] [:link:][step_asn_releases]      **(QA)** Prepare ASN releases (as outlined in the Release Checklist)

### At T-5

  - [ ] [:link:][step_asn_documents]     **(Marketing)** Update the text on the T-5 (from the Printing Press project) and "earliest" ASN documents in the SF portal
  - [ ] [:link:][step_asn_links]         **(Marketing)** (BIND 9 only) Update the BIND -S information document in SF with download links to the new versions
  - [ ] [:link:][step_asn_send]          **(Marketing)** Bulk email eligible customers to check the SF portal
  - [ ] [:link:][step_preannouncement]   **(Marketing)** (BIND 9 only) Send a pre-announcement email to the *bind-announce* mailing list to alert users that the upcoming release will include security fixes

### At T-1

  - [ ] [:link:][step_packager_emails]   **(First IM)** Send notifications to OS packagers

### On the Day of Public Disclosure

  - [ ] [:link:][step_clearance]         **(IM)** Grant QA & Marketing clearance to proceed with public release
  - [ ] [:link:][step_publish]           **(QA/Marketing)** Publish the releases (as outlined in the release checklist)
  - [ ] [:link:][step_matrix]            **(Support)** (BIND 9 only) Add the new CVEs to the vulnerability matrix in the Knowledge Base
  - [ ] [:link:][step_publish_advisory]  **(Support)** Bump Document Version for the Security Advisory and publish it in the Knowledge Base
  - [ ] [:link:][step_notifications]     **(First IM)** Send notification emails to third parties
  - [ ] [:link:][step_mitre]             **(First IM)** Advise MITRE about the disclosed CVEs
  - [ ] [:link:][step_merge_advisory]    **(First IM)** Merge the Security Advisory merge request
  - [ ] [:link:][step_embargo_end]       **(IM)** Inform original reporter (if external) that the security disclosure process is complete
  - [ ] [:link:][step_asn_clear]         **(Marketing)** Update the SF portal to clear the ASN
  - [ ] [:link:][step_customers]         **(Marketing)** Email ASN recipients that the embargo is lifted

### After Public Disclosure

  - [ ] [:link:][step_regression]        **(QA)** Merge a regression test reproducing the bug into all affected (and still maintained) branches

[step_deputy]:            https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#pick-a-deputy-incident-manager
[step_respond]:           https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#respond-to-the-bug-reporter
[step_public_mrs]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#ensure-there-are-no-public-merge-requests-which-inadvertently-disclose-the-issue
[step_assign_cve_id]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#assign-a-cve-identifier
[step_note_cve_info]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#update-this-issue-with-the-assigned-cve-identifier-and-the-cvss-score
[step_versions_affected]: https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#determine-the-range-of-product-versions-affected-including-the-subscription-edition
[step_workarounds]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#determine-whether-workarounds-for-the-problem-exist
[step_coordinate]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#if-necessary-coordinate-with-other-parties
[step_earliest_prepare]:  https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-earliest-notification-text-and-hand-it-off-to-marketing
[step_earliest_send]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#update-earliest-notification-document-in-sf-portal-and-send-bulk-email-to-earliest-customers
[step_advisory_mr]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#create-a-merge-request-for-the-security-advisory-and-include-all-readily-available-information-in-it
[step_reproducer_mr]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-a-private-merge-request-containing-a-system-test-reproducing-the-problem
[step_notify_support]:    https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#notify-support-when-a-reproducer-is-ready
[step_code_analysis]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-a-detailed-explanation-of-the-code-flow-triggering-the-problem
[step_fix_mr]:            https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-a-private-merge-request-with-the-fix
[step_review_fix]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#ensure-the-merge-request-with-the-fix-is-reviewed-and-has-no-outstanding-discussions
[step_review_docs]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#review-the-documentation-changes-introduced-by-the-merge-request-with-the-fix
[step_backports]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-backports-of-the-merge-request-addressing-the-problem-for-all-affected-and-still-maintained-branches-of-a-given-product
[step_finish_advisory]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#finish-preparing-the-security-advisory
[step_meta_issue]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#create-or-update-the-private-issue-containing-links-to-fixes-reproducers-for-all-cves-fixed-in-a-given-release-cycle
[step_changes]:           https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bind-9-only-reserve-a-block-of-changes-placeholders-once-the-complete-set-of-vulnerabilities-fixed-in-a-given-release-cycle-is-determined
[step_merge_fixes]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#merge-the-cve-fixes-in-cve-identifier-order
[step_patches]:           https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-a-standalone-patch-for-the-last-stable-release-of-each-affected-and-still-maintained-product-branch
[step_asn_releases]:      https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-asn-releases-as-outlined-in-the-release-checklist
[step_asn_documents]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#update-the-text-on-the-t-5-from-the-printing-press-project-and-earliest-asn-documents-in-the-sf-portal
[step_asn_links]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bind-9-only-update-the-bind-s-information-document-in-sf-with-download-links-to-the-new-versions
[step_asn_send]:          https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bulk-email-eligible-customers-to-check-the-sf-portal
[step_preannouncement]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bind-9-only-send-a-pre-announcement-email-to-the-bind-announce-mailing-list-to-alert-users-that-the-upcoming-release-will-include-security-fixes
[step_packager_emails]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#send-notifications-to-os-packagers
[step_clearance]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#grant-qa-marketing-clearance-to-proceed-with-public-release
[step_publish]:           https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#publish-the-releases-as-outlined-in-the-release-checklist
[step_matrix]:            https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bind-9-only-add-the-new-cves-to-the-vulnerability-matrix-in-the-knowledge-base
[step_publish_advisory]:  https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bump-document-version-for-the-security-advisory-and-publish-it-in-the-knowledge-base
[step_notifications]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#send-notification-emails-to-third-parties
[step_mitre]:             https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#advise-mitre-about-the-disclosed-cves
[step_merge_advisory]:    https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#merge-the-security-advisory-merge-request
[step_embargo_end]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#inform-original-reporter-if-external-that-the-security-disclosure-process-is-complete
[step_asn_clear]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#update-the-sf-portal-to-clear-the-asn
[step_customers]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#email-asn-recipients-that-the-embargo-is-lifted
[step_regression]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#merge-a-regression-test-reproducing-the-bug-into-all-affected-and-still-maintained-branches

/confidential
