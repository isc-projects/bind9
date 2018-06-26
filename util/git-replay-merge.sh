#!/bin/bash
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e

SELF="$(basename $0)"
SELF="${SELF/-/ }"

STATE_FILE=".git/REPLAY_MERGE"

die() {
	for MESSAGE in "$@"; do
		echo -e "${MESSAGE}" >&2
	done
	exit 1
}

die_with_usage() {
	die "Usage:"								\
	    ""									\
	    "	${SELF} <merge_commit_id> <target_remote> <target_branch>"	\
	    "	${SELF} --continue"						\
	    "	${SELF} --abort"
}

verify_gitlab_cli() {
	which gitlab >/dev/null 2>&1 || \
		die "You need to have gitlab cli installed and configured: "\
		    "" \
		    "$ gem install --user-install gitlab"
}

die_with_continue_instructions() {
	die ""								\
	    "Replay interrupted.  Conflicts need to be fixed manually."	\
	    "When done, run \"${SELF} --continue\"."			\
	    "Use \"${SELF} --abort\" to abort the replay."
}

die_if_wrong_dir() {
	if [[ ! -d ".git" ]]; then
		die "You need to run this command from the toplevel of the working tree."
	fi
}

die_if_not_in_progress() {
	die_if_wrong_dir
	if [[ ! -f "${STATE_FILE}" ]]; then
		die "No replay-merge in progress?"
	fi
}

die_if_in_progress() {
	die_if_wrong_dir
	if [[ -f "${STATE_FILE}" ]]; then
		die "Another replay-merge in progress.  Use --continue or --abort."
	fi
}

die_if_local_behind_target() {
	TARGET_REF_HEAD="$(git rev-list --max-count=1 "${TARGET_REF}")"
	if [[ "$(git merge-base "${TARGET_REF}" "${TARGET_BRANCH}")" != "${TARGET_REF_HEAD}" ]]; then
		die "Local branch ${TARGET_BRANCH} is behind ${TARGET_REF}, cannot merge into it."	\
		    "Update or remove the local branch, then run \"${SELF} --continue\"."		\
		    "Use \"${SELF} --abort\" to abort the replay."
	fi
}

branch_exists() {
	ESCAPED_BRANCH_NAME=${1//\//\\\/}
	BRANCH_REGEX="/^(remotes\/)?${ESCAPED_BRANCH_NAME}$/"
	if [[ -n "$(git branch -a | awk "\$NF ~ ${BRANCH_REGEX} {print \$NF}")" ]]; then
		return 0
	else
		return 1
	fi
}

go() {
	# Process parameters.
	SOURCE_COMMIT="$1"
	TARGET_REMOTE="$2"
	TARGET_BRANCH="$3"
	TARGET_REF="${TARGET_REMOTE}/${TARGET_BRANCH}"
	# Establish the range of commits comprising the source branch.
	REPLAY_COMMIT_RANGE="$(
		git show --format="%P" "${SOURCE_COMMIT}" 2>&1 |
		sed -n "1s/\([0-9a-f]\{40\}\) \([0-9a-f]\{40\}\)/\1..\2/p;"
	)"
	if [[ -z "${REPLAY_COMMIT_RANGE}" ]]; then
		die "${SOURCE_COMMIT} is not a valid merge commit ID."
	fi
	# Extract the name of the source branch.
	SOURCE_BRANCH="$(
		git log --max-count=1 --format="%B" "${SOURCE_COMMIT}" |
		sed -n "s/^Merge branch '\([^'][^']*\).*/\1/p;" |
		head -n 1
	)"
	if [[ -z "${SOURCE_BRANCH}" ]]; then
		die "Unable to extract source branch name from ${SOURCE_COMMIT}."
	fi
	# Ensure the target ref is valid.
	if ! branch_exists "${TARGET_REF}"; then
		die "${TARGET_REF} is not a valid replay target."
	fi
	# Abort if a local branch with the name about to be used for replaying
	# the merge already exists.
	REPLAY_BRANCH="${SOURCE_BRANCH}-${TARGET_BRANCH}"
	if branch_exists "${REPLAY_BRANCH}"; then
		die "Local branch with name ${REPLAY_BRANCH} already exists."	\
		    "Cannot use it for replaying a merge."
	fi
	# Get the name of the currently checked out branch so that it can be
	# checked out again once the replay is finished.
	CHECKED_OUT_BRANCH="$(git branch | awk "\$1 == \"*\" {print \$2}")"
	# Store state in case it needs to be restored later.
	cat <<-EOF > "${STATE_FILE}"
		CHECKED_OUT_BRANCH="${CHECKED_OUT_BRANCH}"
		SOURCE_COMMIT="${SOURCE_COMMIT}"
		SOURCE_BRANCH="${SOURCE_BRANCH}"
		REPLAY_BRANCH="${REPLAY_BRANCH}"
		TARGET_REMOTE="${TARGET_REMOTE}"
		TARGET_BRANCH="${TARGET_BRANCH}"
		TARGET_REF="${TARGET_REF}"
	EOF
	# Announce the plan.
	echo "Attempting to replay ${REPLAY_COMMIT_RANGE} on top of ${TARGET_REF} in ${REPLAY_BRANCH}..."
	# Switch to the replay branch.
	git checkout -t -b "${REPLAY_BRANCH}" "${TARGET_REF}" >/dev/null
	# Try replaying the branch.  If there is any conflict, the command will
	# fail, which means we need to bail and let the user fix the current
	# cherry-pick manually, expecting "git replay-merge --continue" to be
	# used afterwards.  If there is no conflict, just proceed with what
	# --continue would do.
	if ! git cherry-pick -x "${REPLAY_COMMIT_RANGE}"; then
		die_with_continue_instructions
	fi
	resume
}

resume() {
	# If cherry-picking has not yet been completed, resume it.  If it
	# fails, bail.  If if succeeds, we can proceed with merging.
	if [[ -f ".git/sequencer/todo" ]]; then
		if ! git cherry-pick --continue; then
			die_with_continue_instructions
		fi
	fi

	git push ${TARGET_REMOTE} -u ${REPLAY_BRANCH}:${REPLAY_BRANCH}

	REPLAY_COMMIT_TITLE="$(git show --format="%b" "${SOURCE_COMMIT}" 2>&1 | head -1)"

	gitlab create_merge_request 1 "${REPLAY_COMMIT_TITLE}" "{source_branch: '${REPLAY_BRANCH}', target_branch: '${TARGET_BRANCH}'}"
	
	cleanup
	exit 0
}

cleanup() {
	# Restore working copy state from before the replay was started,
	# ignoring any potential errors to prevent "set -e" from interfering.
	{
		git merge --abort
		git cherry-pick --abort
		git checkout "${CHECKED_OUT_BRANCH}"
	} &>/dev/null || true
	rm -f "${STATE_FILE}"
}

case "$1" in
	"--abort")
		die_if_not_in_progress
		source "${STATE_FILE}"
		cleanup
		;;
	"--continue")
		verify_gitlab_cli
		die_if_not_in_progress
		source "${STATE_FILE}"
		resume
		;;
	*)
		if [[ $# -ne 3 ]]; then
			die_with_usage
		fi
		verify_gitlab_cli
		die_if_in_progress
		go "$@"
		;;
esac
