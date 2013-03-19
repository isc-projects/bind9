#!/bin/sh
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
# Usage:
# branchsync.sh [ -i ] [ -c ]
#   -i: interactive mode (don't reset and send mail)
#   -c: continue (conflicts are resolved; edit message and commit)

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
    git log -1 --pretty=format:%s%n%b $2 > orig_commit_msg.tmp
    firstline=`head -1 orig_commit_msg.tmp | sed 's/^\[[a-z0-9_]*\] //'`
    tail -n +2 orig_commit_msg.tmp > remainder.tmp
    firstline="[$BRANCH] $firstline"
    echo $firstline > commit_msg.tmp
    cat remainder.tmp >> commit_msg.tmp
    echo "pulled from $1 by script." >> commit_msg.tmp
    echo "hash: $2" >> commit_msg.tmp
    msg=`cat commit_msg.tmp`
    rm -f orig_commit_msg.tmp commit_msg.tmp remainder.tmp
    git commit --no-verify --no-edit -m "$msg" || exit 1
}

BRANCH=`thisbranch`
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
    git pull origin $BRANCH
    git checkout -f $SOURCEBRANCH
    git pull origin $SOURCEBRANCH
    git checkout -f $BRANCH
fi

# loop through commits looking for ones that should be cherry-picked
git log $SOURCEBRANCH --reverse --format='%H %aN' $LASTHASH..$SOURCEBRANCH | \
  grep -v Tinderbox | cut -d' ' -f1 | {
    while read hash; do
        if git cherry-pick -xn ${hash}; then
            # cherry-pick was clean
            # restore the copyrights file
            git checkout HEAD -- util/copyrights
            # note which hash we've merged
            savehash branchsync.dat $SOURCEBRANCH $hash

            # fix the commit message, and commit
            docommit $SOURCEBRANCH $hash

            # move on to the next commit
            continue
        elif [ -n "$interactive" ]; then
            # interactive mode -- wait for user to fix things
            git checkout HEAD -- util/copyrights
            # note which hash we've merged
            savehash branchsync.dat $SOURCEBRANCH $hash
        else
            # noninteractive mode
            # reset everything
            git reset --hard

            # build mail message
            MESSAGE="Attempt to cherry pick ${hash}\nto $BRANCH failed."
            MESSAGE=$MESSAGE"\nCommit message of change was:\n"
            MESSAGE=$MESSAGE"`git log -1 --pretty=format:%s%n%b ${hash}`"
            subject="Branch sync to $BRANCH failed"

            # send mail
            echo "$MESSAGE" | mail -s "$subject" bind-changes
        fi

        break
    done
}
