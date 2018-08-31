##Release Checklist

 - [ ] Check for the presence of a milestone for the release
    - If there is a milestone, are all the issues for the milestone resolved? (other than this checklist)
 - [ ] Prepare the sources for tarball generation
 - [ ] Change software version and library versions in configure.in
 - [ ] Update CHANGES
 - [ ] Ensure the release notes are correct for this release
 - [ ] Ensure the metainformation is correct for this release
 - [ ] Make sure the tests are passing
 - [ ] Create a tag (name vX_Y_Z[-alphatag], content BIND X.Y.Z[-alphatag], signed with a developer's GPG key): git tag -u <DEVELOPER_KEYID> -a -s -m "BIND X.Y.Z" vX.Y.Z
 - [ ] Push the changes and tag
 - [ ] Create the tarball
 - [ ] Create the Windows zips
 - [ ] Ask QA to sanity check the tarball and zips
 - [ ] Request the signature on the tarballs
 - [ ] Make tarballs and signatures available to download
 - [ ] Edit the release https://gitlab.isc.org/isc-projects/bind9/tags and the NEWS snippet + links to the tarballs
 - [ ] Update DEB and RPM packages

##Communication

 - [ ] Inform support to upload to the web site (nice to give them a heads-up in advance)
       Write release e-mail to bind9-announce, bind-users in case of a major release 
 - [ ] Inform marketing to announce the release
        Post short note to Twitter 
        Update http://en.wikipedia.org/wiki/BIND (mktg)
        Blog post if a major release
