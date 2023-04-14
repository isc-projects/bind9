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

 - [ ] ***(QA)*** Rebase -S editions on top of current open-source versions: `git checkout bind-9.18-sub && git rebase origin/bind-9.18`
 - [ ] ***(QA)*** [Inform](https://gitlab.isc.org/isc-private/bind-qa/-/blob/master/bind9/releng/inform_supp_marketing.py) Support and Marketing of impending release (and give estimated release dates).
 - [ ] ***(QA)*** Ensure there are no permanent test failures on any platform. Check [public](https://gitlab.isc.org/isc-projects/bind9/-/pipelines?scope=all&source=schedule) and [private](https://gitlab.isc.org/isc-private/bind9/-/pipelines?scope=all&source=schedule) scheduled pipelines.
 - [ ] ***(QA)*** Check [Perflab](https://perflab.isc.org/) to ensure there has been no unexplained drop in performance for the versions being released.
 - [ ] ***(QA)*** Check whether all issues assigned to the release milestone are resolved[^1].
 - [ ] ***(QA)*** Ensure that there are no outstanding [merge requests in the private repository](https://gitlab.isc.org/isc-private/bind9/-/merge_requests/)[^1] (Subscription Edition only).
 - [ ] ***(QA)*** [Ensure](https://gitlab.isc.org/isc-private/bind-qa/-/blob/master/bind9/releng/check_backports.py) all merge requests marked for backporting have been indeed backported.
 - [ ] ***(QA)*** [Announce](https://gitlab.isc.org/isc-private/bind-qa/-/blob/master/bind9/releng/inform_code_freeze.py) (on Mattermost) that the code freeze is in effect.

### Before the Tagging Deadline

 - [ ] ***(QA)*** Ensure release notes are correct, ask Support and Marketing to check them as well. [Example](https://gitlab.isc.org/isc-private/bind9/-/merge_requests/510)
 - [ ] ***(QA)*** Add a release marker to `CHANGES`. Examples: [9.18](https://gitlab.isc.org/isc-projects/bind9/-/commit/f14d8ad78c0506fd4247187f2177f8eceeb6b3b9), [9.16](https://gitlab.isc.org/isc-projects/bind9/-/commit/1bcdf21874f99a00da389d723e0ad07dfd70f9f1)
 - [ ] ***(QA)*** Add a release marker to `CHANGES.SE` (Subscription Edition only). [Example](https://gitlab.isc.org/isc-private/bind9/-/commit/0f03d5737bcbdaa1bf713c6db1887b14938c3421)
 - [ ] ***(QA)*** Update BIND 9 version in `configure.ac` ([9.18+](https://gitlab.isc.org/isc-projects/bind9/-/commit/3c85ab7f4c35e6d8acef1393606002a0a8730100)) or `version` ([9.16](https://gitlab.isc.org/isc-projects/bind9/-/merge_requests/7692/diffs?commit_id=1bcdf21874f99a00da389d723e0ad07dfd70f9f1)).
 - [ ] ***(QA)*** Rebuild `configure` using Autoconf on `docs.isc.org` (9.16).
 - [ ] ***(QA)*** Update GitLab settings for all maintained branches to disallow merging to them: [public](https://gitlab.isc.org/isc-projects/bind9/-/settings/repository), [private](https://gitlab.isc.org/isc-private/bind9/-/settings/repository)
 - [ ] ***(QA)*** Tag the releases in the private repository (`git tag -s -m "BIND 9.x.y" v9.x.y`).

### Before the ASN Deadline (for ASN Releases) or the Public Release Date (for Regular Releases)

 - [ ] ***(QA)*** Check that the formatting is correct for HTML and PDF versions of release notes.
 - [ ] ***(QA)*** Check that the formatting of the generated man pages is correct.
 - [ ] ***(QA)*** Verify GitLab CI results [for the tags](https://gitlab.isc.org/isc-private/bind9/-/pipelines?scope=tags) created and sign off on the releases to be published.
 - [ ] ***(QA)*** Update GitLab settings for all maintained branches to allow merging to them again: [public](https://gitlab.isc.org/isc-projects/bind9/-/settings/repository), [private](https://gitlab.isc.org/isc-private/bind9/-/settings/repository)
 - [ ] ***(QA)*** Prepare and merge MRs resetting the release notes and updating the version string for each maintained branch: [9.16](https://gitlab.isc.org/isc-projects/bind9/-/merge_requests/7652/diffs) and [newer](https://gitlab.isc.org/isc-projects/bind9/-/merge_requests/7651/diffs)
 - [ ] ***(QA)*** Announce (on Mattermost) that the code freeze is over.
 - [ ] ***(QA)*** Request signatures for the tarballs, providing their location and checksums. Ask [signers on Mattermost](https://mattermost.isc.org/isc/channels/bind-9-qa).
 - [ ] ***(Signers)*** Ensure that the contents of tarballs and tags are identical.
 - [ ] ***(Signers)*** Validate tarball checksums, sign tarballs, and upload signatures.
 - [ ] ***(QA)*** Verify tarball signatures and check tarball checksums again: Run `publish_bind.sh` on repo.isc.org to pre-publish.
 - [ ] ***(Support)*** Pre-publish ASN and/or Subscription Edition tarballs so that packages can be built.
 - [ ] ***(QA)*** Build and test ASN and/or Subscription Edition packages (in [cloudsmith branch in private repo](https://gitlab.isc.org/isc-private/rpms/bind/-/tree/cloudsmith)). [Example](https://gitlab.isc.org/isc-private/rpms/bind/-/commit/e2512f4cfaf991827a635e374e7e93b27a5f38ba)
 - [ ] ***(QA)*** Prepare the `patches/` subdirectory for each security release (if applicable).
 - [ ] ***(QA)*** Notify Support that the releases have been prepared.
 - [ ] ***(Support)*** Send out ASNs (if applicable).

### On the Day of Public Release

 - [ ] ***(Support)*** Wait for clearance from Security Officer to proceed with the public release (if applicable).
 - [ ] ***(Support)*** Place tarballs in public location on FTP site.
 - [ ] ***(Support)*** Publish links to downloads on ISC website. [Example](https://gitlab.isc.org/website/theme-staging-site/-/commit/1ac7b30b73cb03228df4cd5651fa4e774ac35625)
 - [ ] ***(Support)*** Write release email to *bind-announce*. [Example](https://lists.isc.org/pipermail/bind-announce/2023-March/001231.html)
 - [ ] ***(Support)*** Write email to *bind-users* (if a major release). [Example](https://lists.isc.org/pipermail/bind-users/2022-January/105624.html)
 - [ ] ***(Support)*** Send eligible customers updated links to the Subscription Edition (update the -S edition delivery tickets, even if those links were provided earlier via an ASN ticket).
 - [ ] ***(Support)*** Update tickets in case of waiting support customers.
 - [ ] ***(QA)*** Build and test any outstanding private packages in [private repo](https://gitlab.isc.org/isc-private/rpms/bind/-/tree/cloudsmith). [Example](https://gitlab.isc.org/isc-private/rpms/bind/-/commit/2007d566db81dd9dfd79e571e2f600a3bc284da4)
 - [ ] ***(QA)*** Build [public RPMs](https://gitlab.isc.org/isc-packages/rpms/bind). [Example commit](https://gitlab.isc.org/isc-packages/rpms/bind/-/commit/3b5e851ea7c4e3570371a4878b5461f02a44f8cc) which triggers [Copr builds](https://copr.fedorainfracloud.org/coprs/isc/) automatically
 - [ ] ***(SwEng)*** Build Debian/Ubuntu packages.
 - [ ] ***(SwEng)*** Update Docker files [here](https://gitlab.isc.org/isc-projects/bind9-docker/-/branches) and make sure push is synchronized to [GitHub](https://github.com/isc-projects/bind9-docker). [Docker Hub](https://hub.docker.com/r/internetsystemsconsortium/bind9) should pick it up automatically. [Example](https://gitlab.isc.org/isc-projects/bind9-docker/-/commit/cada7e10e9af951595c98bfffc4bd42512faac05)
 - [ ] ***(QA)*** Inform Marketing of the release.
 - [ ] ***(Marketing)*** Post short note to Twitter.
 - [ ] ***(Marketing)*** Update [Wikipedia entry for BIND](https://en.wikipedia.org/wiki/BIND).
 - [ ] ***(Marketing)*** Write blog article (if a major release).
 - [ ] ***(QA)*** Ensure all new tags are annotated and signed. `git show --show-signature v9.19.12`
 - [ ] ***(QA)*** Push tags for the published releases to the public repository.
 - [ ] ***(QA)*** Merge published release tags (non-linearly) back into the their relevant development/maintenance branches. [Step 7 of the new workflow](https://gitlab.isc.org/isc-projects/bind9/-/merge_requests/6124#new-workflow)
 - [ ] ***(QA)*** Sanitize confidential issues which are assigned to the current release milestone and do not describe a security vulnerability, then make them public.
 - [ ] ***(QA)*** Sanitize [confidential issues](https://gitlab.isc.org/isc-projects/bind9/-/issues/?sort=milestone_due_desc&state=opened&confidential=yes) which are assigned to older release milestones and describe security vulnerabilities, then make them public if appropriate[^2].
 - [ ] ***(QA)*** Update QA tools used in GitLab CI (e.g. Black, PyLint, Sphinx) by modifying the relevant [`Dockerfile`](https://gitlab.isc.org/isc-projects/images/-/merge_requests/228/diffs).
 - [ ] ***(QA)*** Run a pipeline to rebuild all [images](https://gitlab.isc.org/isc-projects/images) used in GitLab CI.
 - [ ] ***(QA)*** Update [`metadata.json`](https://gitlab.isc.org/isc-private/bind-qa/-/blob/master/bind9/releng/metadata.json) with the upcoming release information.

[^1]: If not, use the time remaining until the tagging deadline to ensure all outstanding issues are either resolved or moved to a different milestone.
[^2]: As a rule of thumb, security vulnerabilities which have reproducers merged to the public repository are considered okay for full disclosure.
