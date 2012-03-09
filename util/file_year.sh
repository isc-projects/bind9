#!/bin/sh
# Given a file in the currently checked-out branch of the Git
# repository, find out in what year it was most recently committed.
# Used by merge_copyrights.

rev=`git rev-list HEAD -- "$1" | head -n 1`
git show --pretty=format:%ai $rev | head -n 1 | sed 's;-.*;;'
