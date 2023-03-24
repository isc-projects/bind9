## Release Schedule

**Code Freeze:**

**Tagging Deadline:**

**Public Release:**

## Documentation Review Links

**Closed issues assigned to the milestone without a release note:**

 - []()
 - []()
 - []()

**Merge requests merged into the milestone without a release note:**

 - []()
 - []()
 - []()

**Merge requests merged into the milestone without a `CHANGES` entry:**

 - []()
 - []()
 - []()

## Release Checklist

### Before the Code Freeze

 - [ ] ***(QA)*** Inform Support and Marketing of impending release (and give estimated release dates).
 - [ ] ***(QA)*** Ensure there are no permanent test failures on any platform.
 - [ ] ***(QA)*** Check Perflab to ensure there has been no unexplained drop in performance for the versions being released.
 - [ ] ***(QA)*** Check whether all issues assigned to the release milestone are resolved[^1].
 - [ ] ***(QA)*** Ensure that there are no outstanding merge requests in the private repository[^1] (Subscription Edition only).
 - [ ] ***(QA)*** Ensure all merge requests marked for backporting have been indeed backported.
 - [ ] ***(QA)*** Announce (on Mattermost) that the code freeze is in effect.

### Before the Tagging Deadline

 - [ ] ***(QA)*** Ensure release notes are correct, ask Support and Marketing to check them as well.
 - [ ] ***(QA)*** Add a release marker to `CHANGES`.
 - [ ] ***(QA)*** Add a release marker to `CHANGES.SE` (Subscription Edition only).
 - [ ] ***(QA)*** Update BIND 9 version in `configure.ac` (9.18+) or `version` (9.16).
 - [ ] ***(QA)*** Rebuild `configure` using Autoconf on `docs.isc.org` (9.16).
 - [ ] ***(QA)*** Update GitLab settings for all maintained branches to disallow merging to them.
 - [ ] ***(QA)*** Tag the releases in the private repository (`git tag -s -m "BIND 9.x.y" v9.x.y`).

### Before the ASN Deadline (for ASN Releases) or the Public Release Date (for Regular Releases)

 - [ ] ***(QA)*** Check that the formatting is correct for HTML and PDF versions of release notes.
 - [ ] ***(QA)*** Check that the formatting of the generated man pages is correct.
 - [ ] ***(QA)*** Verify GitLab CI results for the tags created and sign off on the releases to be published.
 - [ ] ***(QA)*** Update GitLab settings for all maintained branches to allow merging to them again.
 - [ ] ***(QA)*** Prepare and merge MRs resetting the release notes and updating the version string for each maintained branch.
 - [ ] ***(QA)*** Announce (on Mattermost) that the code freeze is over.
 - [ ] ***(QA)*** Request signatures for the tarballs, providing their location and checksums.
 - [ ] ***(Signers)*** Ensure that the contents of tarballs and tags are identical.
 - [ ] ***(Signers)*** Validate tarball checksums, sign tarballs, and upload signatures.
 - [ ] ***(QA)*** Verify tarball signatures and check tarball checksums again.
 - [ ] ***(Support)*** Pre-publish ASN and/or Subscription Edition tarballs so that packages can be built.
 - [ ] ***(QA)*** Build and test ASN and/or Subscription Edition packages.
 - [ ] ***(QA)*** Prepare the `patches/` subdirectory for each security release (if applicable).
 - [ ] ***(QA)*** Notify Support that the releases have been prepared.
 - [ ] ***(Support)*** Send out ASNs (if applicable).

### On the Day of Public Release

 - [ ] ***(Support)*** Wait for clearance from Security Officer to proceed with the public release (if applicable).
 - [ ] ***(Support)*** Place tarballs in public location on FTP site.
 - [ ] ***(Support)*** Publish links to downloads on ISC website.
 - [ ] ***(Support)*** Write release email to *bind-announce*.
 - [ ] ***(Support)*** Write email to *bind-users* (if a major release).
 - [ ] ***(Support)*** Send eligible customers updated links to the Subscription Edition (update the -S edition delivery tickets, even if those links were provided earlier via an ASN ticket).
 - [ ] ***(Support)*** Update tickets in case of waiting support customers.
 - [ ] ***(QA)*** Build and test any outstanding private packages.
 - [ ] ***(QA)*** Build public RPMs.
 - [ ] ***(SwEng)*** Build Debian/Ubuntu packages.
 - [ ] ***(SwEng)*** Update Docker images.
 - [ ] ***(QA)*** Inform Marketing of the release.
 - [ ] ***(Marketing)*** Post short note to Twitter.
 - [ ] ***(Marketing)*** Update [Wikipedia entry for BIND](https://en.wikipedia.org/wiki/BIND).
 - [ ] ***(Marketing)*** Write blog article (if a major release).
 - [ ] ***(QA)*** Ensure all new tags are annotated and signed.
 - [ ] ***(QA)*** Push tags for the published releases to the public repository.
 - [ ] ***(QA)*** Merge published release tags (non-linearly) back into the their relevant development/maintenance branches.
 - [ ] ***(QA)*** Sanitize confidential issues which are assigned to the current release milestone and do not describe a security vulnerability, then make them public.
 - [ ] ***(QA)*** Sanitize confidential issues which are assigned to older release milestones and describe security vulnerabilities, then make them public if appropriate[^2].
 - [ ] ***(QA)*** Update QA tools used in GitLab CI (e.g. Black, PyLint, Sphinx) by modifying the relevant `Dockerfile`.
 - [ ] ***(QA)*** Run a pipeline to rebuild all [images](https://gitlab.isc.org/isc-projects/images) used in GitLab CI.
 - [ ] ***(QA)*** Update [`metadata.json`](https://gitlab.isc.org/isc-private/bind-qa/-/blob/master/bind9/releng/metadata.json) with the upcoming release information.

[^1]: If not, use the time remaining until the tagging deadline to ensure all outstanding issues are either resolved or moved to a different milestone.
[^2]: As a rule of thumb, security vulnerabilities which have reproducers merged to the public repository are considered okay for full disclosure.
