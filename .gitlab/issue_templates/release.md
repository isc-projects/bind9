## Release Checklist

 - [ ] (Manager) Check for the presence of a milestone for the release:
    - If there is a milestone, are all the issues for the milestone resolved? (other than this checklist).
 - [ ] (Manager) Inform Support/Marketing of impending release (and give estimated release dates).
 - (SwEng) Prepare the sources for tarball generation:
   - [ ] Check perflab to ensure there has been no unexplained drop in performance for the version being released.
   - [ ] Ensure that there are no outstanding merge requests in the private repository (subscription version only).
   - [ ] Update API files for libraries with new version information.
   - [ ] Change software version and library versions in configure.in (new major release only).
   - [ ] Rebuild configure using autoconf on docs.isc.org.
   - [ ] Update CHANGES.
   - [ ] Update CHANGES.SE (subscription branch only).
   - [ ] Update "version".
   - [ ] Update "readme.md".
   - Check the release notes are correct:
     - [ ] Compare content with merge requests for the release.
     - [ ] Check formatting.
   - [ ] Build documentation on docs.isc.org.
   - [ ] Commit changes and make sure the gitlab-ci tests are passing.
   - [ ] Push the changes and tag ("alphatag" is an optional string such as "b1", "rc1" etc.). (```git tag -u <DEVELOPER_KEYID> -a -s -m "BIND 9.X.Y[alphatag]" v9_X_Y[alphatag]```)
   - [ ] If this is the first tag for a release (e.g. beta), create a release branch named `release_v9_X_Y` (this allows development to continue on the release branch whilst release engineering continues).
 - [ ] (SwEng) Run the "make release" Jenkins job to produce the tarballs and zips.
 - [ ] (SwEng) Ask QA to sanity check the tarball and zips (passing to them the number of the Jenkins job).
 - [ ] (QA) Sanity check the tarballs.
 - [ ] (QA) Request the signature on the tarballs.
 - [ ] (QA) Check signatures on tarballs.
 - [ ] (QA) Tell Support to handle notification of release.
 - [ ] (Manager) Inform Marketing of the release
 - [ ] (Manager) Update the internal [BIND release dates wiki page](https://wiki.isc.org/bin/view/Main/BindReleaseDates) when public announcement has been made.
 - [ ] (SwEng) Push tags for the published releases to the public repository.
 - [ ] (SwEng) Update DEB and RPM packages.
 - [ ] (SwEng) Merge the automatically prepared `prep 9.X.Y` commit which updates `version` and documentation on the release branch into the relevant maintenance branch (`v9_X`).

## Support
 - [ ] Make tarballs and signatures available to download.
 - [ ] Write release email to bind9-announce.
 - [ ] Write email to bind9-users (if a major release).
 - [ ] Update tickets in case of waiting support customers.

## Marketing
 - [ ] Post short note to Twitter.
 - [ ] Update [Wikipedia entry for BIND](http://en.wikipedia.org/wiki/BIND).
 - [ ] Write blog article (if a major release).
