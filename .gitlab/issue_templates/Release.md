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

### Before the Tagging Deadline

 - [ ] ***(QA)*** Look for outstanding documentation issues (e.g. `CHANGES` mistakes) and address them if any are found.
 - [ ] ***(QA)*** Ensure release notes are correct, ask Support and Marketing to check them as well.
 - [ ] ***(QA)*** Update API files for libraries with new version information.
 - [ ] ***(QA)*** Change software version and library versions in `configure.ac` (new major release only).
 - [ ] ***(QA)*** Rebuild `configure` using Autoconf on `docs.isc.org`.
 - [ ] ***(QA)*** Update `CHANGES`.
 - [ ] ***(QA)*** Update `CHANGES.SE` (Subscription Edition only).
 - [ ] ***(QA)*** Update `README.md`.
 - [ ] ***(QA)*** Update `version`.
 - [ ] ***(QA)*** Build documentation on `docs.isc.org`.
 - [ ] ***(QA)*** Check that the formatting is correct for text, PDF, and HTML versions of release notes.
 - [ ] ***(QA)*** Tag the releases in the private repository (`git tag -s -m "BIND 9.x.y" v9_x_y`).

### Before the ASN Deadline (for ASN Releases) or the Public Release Date (for Regular Releases)

 - [ ] ***(QA)*** Verify GitLab CI results for the tags created and prepare a QA report for the releases to be published.
 - [ ] ***(QA)*** Request signatures for the tarballs, providing their location and checksums.
 - [ ] ***(Signers)*** Validate tarball checksums, sign tarballs, and upload signatures.
 - [ ] ***(QA)*** Verify tarball signatures and check tarball checksums again.
 - [ ] ***(Support)*** Pre-publish ASN and/or Subscription Edition tarballs so that packages can be built.
 - [ ] ***(QA)*** Build and test ASN and/or Subscription Edition packages.
 - [ ] ***(QA)*** Notify Support that the releases have been prepared.
 - [ ] ***(Support)*** Send out ASNs (if applicable).

### On the Day of Public Release

 - [ ] ***(Support)*** Wait for clearance from Security Officer to proceed with the public release (if applicable).
 - [ ] ***(Support)*** Place tarballs in public location on FTP site.
 - [ ] ***(Support)*** Publish links to downloads on ISC website.
 - [ ] ***(Support)*** Write release email to *bind-announce*.
 - [ ] ***(Support)*** Write email to *bind-users* (if a major release).
 - [ ] ***(Support)*** Send eligible customers updated links to the Subscription Edition.
 - [ ] ***(Support)*** Update tickets in case of waiting support customers.
 - [ ] ***(QA)*** Build and test any outstanding private packages.
 - [ ] ***(QA)*** Build public packages (`*.deb`, RPMs).
 - [ ] ***(QA)*** Inform Marketing of the release.
 - [ ] ***(QA)*** Update the internal [BIND release dates wiki page](https://wiki.isc.org/bin/view/Main/BindReleaseDates) when public announcement has been made.
 - [ ] ***(Marketing)*** Post short note to Twitter.
 - [ ] ***(Marketing)*** Update [Wikipedia entry for BIND](https://en.wikipedia.org/wiki/BIND).
 - [ ] ***(Marketing)*** Write blog article (if a major release).
 - [ ] ***(QA)*** Ensure all new tags are annotated and signed.
 - [ ] ***(QA)*** Push tags for the published releases to the public repository.
 - [ ] ***(QA)*** Merge the automatically prepared `prep 9.x.y` commit which updates `version` and documentation on the release branch into the relevant maintenance branch (`v9_x`).
 - [ ] ***(QA)*** For each maintained branch, update the `BIND_BASELINE_VERSION` variable for the `abi-check` job in `.gitlab-ci.yml` to the latest published BIND version tag for a given branch.
 - [ ] ***(QA)*** Prepare empty release notes for the next set of releases.
 - [ ] ***(QA)*** Sanitize all confidential issues assigned to the release milestone and make them public.
 - [ ] ***(QA)*** Update QA tools used in GitLab CI (e.g. Flake8, PyLint) by modifying the relevant `Dockerfile`.

[^1]: If not, use the time remaining until the tagging deadline to ensure all outstanding issues are either resolved or moved to a different milestone.
