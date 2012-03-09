#!/bin/sh
# Find the list of files that have been touched in the Git repository
# during the current calendar year.  This is done by walking backwards
# through the output of "git whatchanged" until a year other than the
# current one is seen.  Used by merge_copyrights.

thisyear=`date +%Y`
git whatchanged --pretty="date %ai" --date=iso8601 | awk -vre="${thisyear}-" '
    $1 == "date" && $2 !~ re { exit(0); }
    $1 == "date" { next; }
    NF == 0 { next; }
    $(NF-1) ~ /[AM]/ { print "./" $NF }' | sort | uniq
