#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# branchsync:
# pull in changes from a main BIND 9 release branch to a subscription
# branch (e.g., from v9_9 to v9_9_sub).  This excludes commits from the
# 'tinderbox' user (copyright updates and doc regeneration) because those
# will be taken care of in the subscription branch itself.
#
# Most of the time, changes in the main branch will cherry-pick cleanly
# into the subscription branch. When one fails, we reset to the last
# commit that went cleanly, and send mail -- or, if running in interactive
# mode, we stop and allow the user to resolve conflicts.
#
# NOTE: This does not push changes to the repository; currently that's up
# to the caller.
#
# Usage:
# branchsync.sh [ -i ] [ -c ]
#   -i: interactive mode (don't reset and send mail)
#   -c: continue (conflicts are resolved; edit message and commit)

restore_files () {
    # restore the copyrights and api files
    git checkout HEAD -- util/copyrights lib/*/api
    # restore the generated documentation
    git checkout HEAD -- doc/arm/*.html doc/arm/Bv9ARM.pdf
    git checkout HEAD -- bin/*/*.html bin/*/*.[0-9]
    # don't update the EXCLUDED file
    if [ -f EXCLUDED ]; then
        git checkout HEAD -- EXCLUDED
    fi
}

savehash () {
    cat <<EOF > $1.new
SOURCEBRANCH=$2
LASTHASH=$3
EOF
    mv -f $1.new $1
    git add branchsync.dat
}

thisbranch () {
    git branch | grep '^\*' | cut -b3-
}

docommit () {
    # skip the commit if we're only updating branchsync.dat
    status=`git status -suno | grep branchsync.dat`
    if [ -z "$status" ]; then
        return
    fi

    # pull in the log message from the cherry-picked commit
    git log -1 --pretty=format:%s%n%b $2 > orig_commit_msg.tmp
    author=`git log -1 --pretty=format:"%aN <%aE>" $2`
    firstline=`head -1 orig_commit_msg.tmp | sed 's/^\[[a-z0-9_]*\] //'`
    tail -n +2 orig_commit_msg.tmp > remainder.tmp
    firstline="[$BRANCH] $firstline"
    echo $firstline > commit_msg.tmp
    cat remainder.tmp >> commit_msg.tmp
    echo "pulled from $1 by script." >> commit_msg.tmp
    echo "hash: $2" >> commit_msg.tmp
    msg=`cat commit_msg.tmp`
    rm -f orig_commit_msg.tmp commit_msg.tmp remainder.tmp

    # commit
    git commit --no-verify --no-edit --author="$author" -m "$msg" || exit 1
}

BRANCH=`thisbranch`

if [ ! -f branchsync.dat ]; then
    echo "$0: branchsync data file not found"
    exit 0
fi

. branchsync.dat

# check arguments
interactive=
continuing=
case $1 in
    '-i') interactive=yes
          ;;
    '-c') docommit $SOURCEBRANCH $LASTHASH
          interactive=yes
          continuing=yes
          ;;
    *)    if [ $# -ne 0 ]; then
             echo "Usage: $0 [ -i ] [ -c ]" 1>&2
             exit 1
          fi
          ;;
esac

if [ -z "$continuing" ]; then
    status=`git status -suno`
    if [ -n "$status" ]; then
         echo "Work tree is not clean. Clean up, or run with -c:"
         echo "$status"
         exit 1
    fi

    # make sure both branches are synced to the source repository
    git pull origin $BRANCH > /dev/null 2>&1
    git checkout -f $SOURCEBRANCH > /dev/null 2>&1
    git pull origin $SOURCEBRANCH > /dev/null 2>&1
    git checkout -f $BRANCH > /dev/null 2>&1
fi

# loop through commits looking for ones that should be cherry-picked
git log $SOURCEBRANCH --first-parent --reverse --format='%H %aN' $LASTHASH..$SOURCEBRANCH | \
  awk '$0 !~ /Tinderbox/ {print $1}' | {
    while read hash; do
        mainline=
        if [ `git cat-file -p ${hash} | grep '^parent [0-9a-f][0-9a-f]*$' | wc -l` -gt 1 ]; then
            mainline="-m 1 "
        fi
        if git cherry-pick ${mainline} -xn ${hash}; then
            # cherry-pick was clean
            # restore the files that we don't want updated automatically
            restore_files

            # note which hash we're merging
            savehash branchsync.dat $SOURCEBRANCH $hash

            # fix the commit message, and commit
            docommit $SOURCEBRANCH $hash

            # move on to the next commit
            continue
        elif [ -n "$interactive" ]; then
            # interactive mode -- wait for user to fix things
            # first restore the files that we don't want updated automatically
            restore_files

            # note which hash we're merging
            savehash branchsync.dat $SOURCEBRANCH $hash
        else
            # noninteractive mode
            # reset everything
            git reset --hard

            # build mail message
            subject="Branch sync to $BRANCH failed"
            cat << EOF > /tmp/branchmsg.$$
Attempt to cherry pick ${hash}
to $BRANCH failed.

Commit message of change was:
`git log -1 --pretty=format:%s%n%b ${hash}`
EOF

            # send mail
            cat /tmp/branchmsg.$$ | mail -s "$subject" bind-changes@isc.org
            rm /tmp/branchmsg.$$
        fi

        break
    done
}
