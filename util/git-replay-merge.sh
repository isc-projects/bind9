#!/bin/bash
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e

SELF="$(basename $0)"
SELF="${SELF/-/ }"

STATE_FILE=".git/REPLAY_MERGE"
DONT_PUSH=${DONT_PUSH:=false}
DONT_ACCEPT=${DONT_ACCEPT:=false}

GITLAB_API_ENDPOINT=${GITLAB_API_ENDPOINT:=https://gitlab.isc.org/api/v4}
GITLAB_URI=${GITLAB_URI:=$(echo $GITLAB_API_ENDPOINT | cut -f 1-3 -d /)}
GITLAB_PROJECT_ID=${GITLAB_PROJECT_ID:=1}
GITLAB_PROJECT_GROUP=${GITLAB_PROJECT_GROUP:=isc-projects}
GITLAB_PROJECT_NAME=${GITLAB_PROJECT_NAME:=bind9}

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
	    "	${SELF} --no-push"						\
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

die_before_push() {
	die ""										\
	    "Replay finished locally.  Now check the result in ${REPLAY_BRANCH}."	\
	    "When done, run \"${SELF} --continue\" to push and create MR in gitlab."	\
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

	if [[ "$DONT_PUSH" = "true" ]]; then
		die_before_push
	fi

	if [[ "$DONT_ACCEPT" = "true" ]]; then
		AUTOMERGE=""
	else
		AUTO_MERGE="-o merge_request.merge_when_pipeline_succeeds"
	fi

	git push -u ${TARGET_REMOTE} \
	    -o merge_request.create \
	    -o merge_request.remove_source_branch \
	    -o "merge_request.target=${TARGET_BRANCH}" \
	    ${AUTO_MERGE} \
	    "${REPLAY_BRANCH}:${REPLAY_BRANCH}"

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

cd $(git rev-parse --show-toplevel)

next_action="go"
while [[ $# -ge 1 ]]; do
	case "$1" in
		"--no-push")
			DONT_PUSH=true
			;;
		"--push")
			DONT_PUSH=false
			;;
		"--abort")
			die_if_not_in_progress
			source "${STATE_FILE}"
			next_action="cleanup"
			;;
		"--continue")
			verify_gitlab_cli
			die_if_not_in_progress
			source "${STATE_FILE}"
			next_action="resume"
			;;
		*)
			if [[ $# -ne 3 ]]; then
				die_with_usage
			fi
			break
			;;
	esac
	shift
done

if [[ "DONT_PUSH" = "false" ]]; then
	verify_gitlab_cli
fi

$next_action "$@"
