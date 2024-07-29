############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

import glob
import os
import re

import gitlab

# Helper functions and variables


def added_lines(target_branch, paths):
    import subprocess

    # Hazard fetches the target branch itself, so there is no need to fetch it
    # explicitly using `git fetch --depth 1000 origin <target_branch>`.  The
    # refs/remotes/origin/<target_branch> ref is also expected to be readily
    # usable by the time this file is executed.

    diff = subprocess.check_output(
        ["/usr/bin/git", "diff", f"origin/{target_branch}...", "--"] + paths
    )
    added_lines = []
    for line in diff.splitlines():
        if line.startswith(b"+") and not line.startswith(b"+++"):
            added_lines.append(line)
    return added_lines


def lines_containing(lines, string):
    return [l for l in lines if bytes(string, "utf-8") in l]


changes_issue_or_mr_id_regex = re.compile(rb"\[(GL [#!]|RT #)[0-9]+\]")
rdata_regex = re.compile(r"lib/dns/rdata/")
mr_issue_link_regex = re.compile(r"^(Closes|Fixes):?\s*[^\n]*#[0-9]+", re.MULTILINE)

modified_files = danger.git.modified_files
affected_files = (
    danger.git.modified_files + danger.git.created_files + danger.git.deleted_files
)
mr_title = re.sub(r"^Draft:\s*", r"", danger.gitlab.mr.title)
mr_labels = danger.gitlab.mr.labels
source_branch = danger.gitlab.mr.source_branch
target_branch = danger.gitlab.mr.target_branch
is_backport = "Backport" in mr_labels or "Backport::Partial" in mr_labels
is_full_backport = is_backport and "Backport::Partial" not in mr_labels

gl = gitlab.Gitlab(
    url=f"https://{os.environ['CI_SERVER_HOST']}",
    private_token=os.environ["BIND_TEAM_API_TOKEN"],
)
proj = gl.projects.get(os.environ["CI_PROJECT_ID"])
mr = proj.mergerequests.get(os.environ["CI_MERGE_REQUEST_IID"])

###############################################################################
# MERGE REQUEST INFORMATION
###############################################################################
#
# - FAIL if the MR title doesn't have the expected format
#
# - FAIL if the MR title doesn't contain changelog action

MR_TITLE_RE = re.compile(
    r"^(\[9\.[0-9]{2}(-S)?\])?\s*(\[[^]]*\]\s*)?((chg|fix|new|rem|sec):)?\s*((dev|usr|pkg|doc|test)\s*:)?\s*([^\n]*)$",
)
mr_title_match = MR_TITLE_RE.match(mr_title)
mr_title_cve = mr_title_match.group(3) if mr_title_match else None
mr_title_action = mr_title_match.group(5) if mr_title_match else None
mr_title_audience = mr_title_match.group(7) if mr_title_match else None

if not mr_title_match:
    fail("Merge request's title is invalid. Fix it or contact QA for assistance.")
else:
    if mr_title_action is None:
        fail(
            "Add one of `chg:`|`fix:`|`new:`|`rem:`|`sec:` to the MR title to categorize this change."
        )

###############################################################################
# BRANCH NAME
###############################################################################
#
# - FAIL if the source branch of the merge request includes an old-style
#   "-v9_x" or "-v9.x" suffix.

branch_name_regex = r"^(?P<base>.*?)(?P<suffix>-v9[_.](?P<version>[0-9]+))$"
match = re.match(branch_name_regex, source_branch)
if match:
    fail(
        f"Source branch name `{source_branch}` includes an old-style version "
        f"suffix (`{match.group('suffix')}`). Using such suffixes is now "
        "deprecated. Please resubmit the merge request with the branch name "
        f"set to `{match.group('base')}-bind-9.{match.group('version')}`."
    )

###############################################################################
# COMMIT MESSAGES
###############################################################################
#
# - FAIL if any of the following is true for any commit on the MR branch:
#
#     * The subject line starts with "fixup!", "amend!" or "Apply suggestion".
#
#     * The subject line starts with a prohibited word indicating a work in
#       progress commit (e.g. "WIP").
#
#     * The subject line contains a changelog action.
#
#     * The subject line contains a trailing dot.
#
#     * There is no empty line between the subject line and the log message.
#
# - WARN if any of the following is true for any commit on the MR branch:
#
#     * The length of the subject line for a non-merge commit exceeds 72
#       characters.
#
#     * There is no log message present (i.e. commit only has a subject) and
#       the subject line does not contain any of the following strings:
#       "fixup!", " CHANGES ", " release note".
#
#     * Any line of the log message is longer than 72 characters.  This rule is
#       not evaluated for:
#
#         - lines starting with four spaces, which allows long lines to be
#           included in the commit log message by prefixing them with four
#           spaces (useful for pasting compiler warnings, static analyzer
#           messages, log lines, etc.),
#
#         - lines which contain references (i.e. those starting with "[1]",
#           "[2]", etc.) which allows e.g. long URLs to be included in the
#           commit log message.

PROHIBITED_WORDS_RE = re.compile(
    "^(WIP|wip|DROP|drop|DROPME|checkpoint|experiment|TODO|todo)[^a-zA-Z]"
)
fixup_error_logged = False
for commit in danger.git.commits:
    message_lines = commit.message.splitlines()
    subject = message_lines[0]
    is_merge = len(commit.parents) >= 2
    is_fixup = (
        subject.startswith("fixup!")
        or subject.startswith("amend!")
        or subject.startswith("Apply suggestion")
    )
    if not fixup_error_logged and is_fixup:
        fail(
            "Fixup commits are still present in this merge request. "
            "Please squash them before merging."
        )
        fixup_error_logged = True
    match = PROHIBITED_WORDS_RE.search(subject)
    if match:
        fail(
            f"Prohibited keyword `{match.groups()[0]}` detected "
            f"at the start of a subject line in commit {commit.sha}."
        )
    match = MR_TITLE_RE.match(subject)
    if match and match.group(5) is not None and not is_merge:
        fail(
            f"Changelog action `{match.group(5)}` detected in non-merge"
            f"commit {commit.sha}. Use MR title instead."
        )
    if len(subject) > 72 and not is_merge and not is_fixup:
        warn(
            f"Subject line for commit {commit.sha} is too long: "
            f"```{subject}``` ({len(subject)} > 72 characters)."
        )
    if subject[-1] == ".":
        fail(f"Trailing dot found in the subject of commit {commit.sha}.")
    if len(message_lines) > 1 and message_lines[1]:
        fail(f"No empty line after subject for commit {commit.sha}.")
    if (
        len(message_lines) < 3
        and "fixup! " not in subject
        and "CHANGES " not in subject
        and "release note" not in subject.lower()
        and "GL #" not in subject
    ):
        warn(f"Please write a log message for commit {commit.sha}.")
    for line in message_lines[2:]:
        if (
            len(line) > 72
            and not line.startswith("    ")
            and not re.match(r"\[[0-9]+\]", line)
        ):
            warn(
                f"Line too long in log message for commit {commit.sha}: "
                f"```{line}``` ({len(line)} > 72 characters)."
            )

###############################################################################
# MILESTONE
###############################################################################
#
# FAIL if the merge request is not assigned to any milestone.

if not danger.gitlab.mr.milestone:
    fail("Please assign this merge request to a milestone.")

###############################################################################
# BACKPORT & VERSION LABELS
###############################################################################
#
# FAIL if any of the following is true for the merge request:
#
# * The MR has any "Affects v9.x" label(s) set.  These should only be used for
#   issues.
#
# * The MR is marked as Backport and the number of version labels set is
#   different than 1.  (For backports, the version label is used for indicating
#   its target branch.  This is a rather ugly attempt to address a UI
#   deficiency - the target branch for each MR is not visible on milestone
#   dashboards.)
#
# * The MR is not marked as "Backport" nor any version label is set.  (If the
#   merge request is not a backport, version labels are used for indicating
#   backporting preferences.)
#
# * The Backport MR doesn't have target branch in the merge request title.
#
# * The Backport MR doesn't link to the original MR is its description.
#
# * The original MR linked to from Backport MR hasn't been merged.

BACKPORT_OF_RE = re.compile(
    r"Backport\s+of.*(merge_requests/|!)([0-9]+)", flags=re.IGNORECASE
)
VERSION_LABEL_RE = re.compile(r"v9.([0-9]+)(-S)?")
version_labels = [l for l in mr_labels if l.startswith("v9.")]
affects_labels = [l for l in mr_labels if l.startswith("Affects v9.")]
if affects_labels:
    fail(
        "This MR is marked with at least one *Affects v9.x* label. "
        "Please remove them as they should only be used for issues."
    )
if is_backport:
    if len(version_labels) != 1:
        fail(
            "This MR was marked as *Backport*. "
            "Please also set exactly one version label (*v9.x*)."
        )
    else:
        minor_ver, edition = VERSION_LABEL_RE.search(version_labels[0]).groups()
        edition = "" if edition is None else edition
        title_re = f"^\\[9.{minor_ver}{edition}\\]"
        match = re.search(title_re, mr_title)
        if match is None:
            fail(
                "Backport MRs must have their target version in the title. "
                f"Please put `[9.{minor_ver}{edition}]` at the start of the MR title."
            )
    backport_desc = BACKPORT_OF_RE.search(danger.gitlab.mr.description or "")
    if backport_desc is None:
        fail(
            "Backport MRs must link to the original MR. Please put "
            "`Backport of MR !XXXX` in the MR description."
        )
    else:  # backport MR is linked to original MR
        original_mr_id = backport_desc.groups()[1]
        original_mr = proj.mergerequests.get(original_mr_id)
        if original_mr.state != "merged":
            fail(
                f"Original MR !{original_mr_id} has not been merged. "
                "Please re-run `danger` check once it's merged."
            )
        else:  # check for commit IDs once original MR is merged
            original_mr_commits = list(original_mr.commits(all=True))
            backport_mr_commits = list(mr.commits(all=True))
            for orig_commit in original_mr_commits:
                for backport_commit in backport_mr_commits:
                    if orig_commit.id in backport_commit.message:
                        break
                else:
                    msg = (
                        f"Commit {orig_commit.id} from original MR !{original_mr_id} "
                        "is not referenced in any of the backport commits."
                    )
                    if not is_full_backport:
                        message(msg)
                    else:
                        msg += (
                            " Please use `-x` when cherry-picking to include "
                            "the full original commit ID. Alternately, use the "
                            "`Backport::Partial` label if not all original "
                            "commits are meant to be backported."
                        )
                        fail(msg)
else:
    if not version_labels:
        fail(
            "If this merge request is a backport, set the *Backport* label and "
            "a single version label (*v9.x*) indicating the target branch. "
            "If not, set version labels for all targeted backport branches."
        )

###############################################################################
# OTHER LABELS
###############################################################################
#
# WARN if any of the following is true for the merge request:
#
# * The "Review" label is not set.  (It may be intentional, but rarely is.)
#
# * The "Review" label is set, but the "LGTM" label is not set.  (This aims to
#   remind developers about the need to set the latter on merge requests which
#   passed review.)

approved = mr.approvals.get().approved
if "Review" not in mr_labels:
    warn(
        "This merge request does not have the *Review* label set. "
        "Please set it if you would like the merge request to be reviewed."
    )
elif not approved:
    warn(
        "This merge request is currently in review. "
        "It should not be merged until it is approved."
    )

###############################################################################
# Changelog entries
###############################################################################
#
# FAIL if any of the following is true:
#
# * The merge request title doesn't produce a changelog entry, but it does not have
#   the "No CHANGES" label set.
#
# * The merge request title produces a changelog entry, but it has the "No CHANGES"
#   label set.

changes_modified = mr_title_audience in ["usr", "pkg", "dev"]
no_changes_label_set = "No CHANGES" in mr_labels
if not changes_modified and not no_changes_label_set:
    fail(
        "MR title doesn't produce a new changelog entry. "
        "Add a `dev:`|`usr:`|`pkg:` audience to MR title or set the *No CHANGES* label."
    )
if changes_modified and no_changes_label_set:
    fail(
        "MR title produces a new changelog entry. Unset the *No Changes* label "
        "or remove the `dev:`|`usr:`|`pkg:` audience from the MR title."
    )

###############################################################################
# RELEASE NOTES
###############################################################################
#
# - FAIL if any of the following is true:
#
#     * The merge request does not update release notes and has the "Release
#       Notes" label set.  (This attempts to point out missing release notes.)
#
#     * The merge request updates release notes but does not have the "Release
#       Notes" label set.  (This ensures that merge requests updating release
#       notes can be easily found using the "Release Notes" label.)
#
#     * A file was added to or deleted from the lib/dns/rdata/ subdirectory but
#       release notes were not modified. This is probably a mistake because new
#       RR types are a user-visible change (and so is removing support for
#       existing ones).
#
#     * "Release notes" and "No CHANGES" labels are both set at the same time.
#       (If something is worth a release note, it should surely show up in
#       CHANGES.) MRs with certain labels set ("Documentation", "Release") are
#       exempt because these are typically used during release process.
#
# - WARN if any of the following is true:
#
#     * This merge request does not update release notes and has the "Customer"
#       label set.  (Except for trivial changes, all merge requests which may
#       be of interest to customers should include a release note.)
#
#     * This merge request updates release notes, but no GitLab issue was
#       linked with the `Closes` or `Fixes` keyword in the MR description.

release_notes_changed = mr_title_audience in ["usr", "pkg"]
release_notes_label_set = "Release Notes" in mr_labels
if not release_notes_changed:
    if release_notes_label_set:
        fail(
            "This merge request has the *Release Notes* label set. "
            "Update the MR title to include `usr:`|`pkg:` audience or "
            "unset the *Release Notes* label."
        )
    elif "Customer" in mr_labels:
        warn(
            "This merge request has the *Customer* label set. "
            "Update the MR title to include `usr:`|`pkg:` audience "
            "unless the changes introduced are trivial."
        )
    rdata_types_add_rm = list(
        filter(rdata_regex.match, danger.git.created_files + danger.git.deleted_files)
    )
    if rdata_types_add_rm:
        fail(
            "This merge request adds new files to `lib/dns/rdata/` and/or "
            "deletes existing files from that directory, which almost certainly "
            "means that it adds support for a new RR type or removes support "
            "for an existing one. Update the MR title to include `usr:` audience."
        )
if release_notes_changed and not release_notes_label_set:
    fail(
        "The MR title produces a release note. Set the *Release Notes* label "
        "or remove the `usr:`|`pkg:` audience from the MR title."
    )
if (
    release_notes_label_set
    and no_changes_label_set
    and not ("Documentation" in mr_labels or "Release" in mr_labels)
):
    fail(
        "This merge request is labeled with both *Release notes* and *No CHANGES*. "
        "A user-visible change should also be mentioned in the changelog."
    )

if release_notes_changed and not mr_issue_link_regex.search(
    danger.gitlab.mr.description
):
    warn("No issue was linked via `Closes`|`Fixes` in the MR description.")

###############################################################################
# CVE IDENTIFIERS
###############################################################################
#
# WARN if the merge request title indicates a security issue, but there is no
# CVE identifier in the MR title.

if mr_title_action == "sec" and (mr_title_cve is None or "CVE-20" not in mr_title_cve):
    warn(
        "This merge request fixes a security issue. "
        "Please add `[CVE-XXXX-YYYY]` to the MR title if a CVE was issued."
    )

###############################################################################
# PAIRWISE TESTING
###############################################################################
#
# FAIL if the merge request adds any new ./configure switch without an
# associated annotation used for pairwise testing.

configure_added_lines = added_lines(target_branch, ["configure.ac"])
switches_added = lines_containing(
    configure_added_lines, "AC_ARG_ENABLE"
) + lines_containing(configure_added_lines, "AC_ARG_WITH")
annotations_added = lines_containing(configure_added_lines, "# [pairwise: ")
if switches_added:
    if len(switches_added) > len(annotations_added):
        fail(
            "This merge request adds at least one new `./configure` switch that "
            "is not annotated for pairwise testing purposes."
        )
    else:
        message(
            "**Before merging**, please start a full CI pipeline for this "
            "branch with the `PAIRWISE_TESTING` variable set to any "
            "non-empty value (e.g. `1`). This will cause the `pairwise` "
            "job to exercise the new `./configure` switches."
        )

###############################################################################
# PRE-RELEASE TESTING
###############################################################################
#
# WARN if the merge request is marked with the "Security" label, but not with
# the label used for marking merge requests for pre-release testing (if the
# latter is defined by the relevant environment variable).

pre_release_testing_label = os.getenv("PRE_RELEASE_TESTING_LABEL")
if (
    pre_release_testing_label
    and "Security" in mr_labels
    and pre_release_testing_label not in mr_labels
):
    warn(
        "This merge request is marked with the *Security* label, but it is not "
        f"marked for pre-release testing (*{pre_release_testing_label}*)."
    )

###############################################################################
# USER-VISIBLE LOG LEVELS
###############################################################################
#
# WARN if the merge request adds new user-visible log messages (INFO or above)

user_visible_log_levels = [
    "ISC_LOG_INFO",
    "ISC_LOG_NOTICE",
    "ISC_LOG_WARNING",
    "ISC_LOG_ERROR",
    "ISC_LOG_CRITICAL",
]
source_added_lines = added_lines(target_branch, ["*.[ch]"])
for log_level in user_visible_log_levels:
    if lines_containing(source_added_lines, log_level):
        warn(
            "This merge request adds new user-visible log messages with "
            "level INFO or above. Please double-check log levels and make "
            "sure none of the messages added is a leftover debug message."
        )
        break

###############################################################################
# SYSTEM TEST FILES
###############################################################################
#
# FAIL if newly added system test directory contains an underscore (invalid char)
# FAIL if there are no pytest files in the system test directory
# FAIL if the pytest glue file for tests.sh is missing

TESTNAME_CANDIDATE_RE = re.compile(r"bin/tests/system/([^/]+)")
testnames = set()
for path in affected_files:
    match = TESTNAME_CANDIDATE_RE.search(path)
    if match is not None:
        testnames.add(match.groups()[0])

for testname in testnames:
    dirpath = f"bin/tests/system/{testname}"
    if (
        not os.path.isdir(dirpath)
        or testname.startswith(".")
        or testname.startswith("_")
        or testname == "isctest"
    ):
        continue
    if "_" in testname:
        fail(
            f"System test directory `{testname}` may not contain an underscore, "
            "use hyphen instead."
        )
    if not glob.glob(f"{dirpath}/**/tests_*.py", recursive=True):
        fail(
            f"System test directory `{testname}` doesn't contain any "
            "`tests_*.py` pytest file."
        )
    tests_sh_exists = os.path.exists(f"{dirpath}/tests.sh")
    glue_file_name = f"tests_sh_{testname.replace('-', '_')}.py"
    tests_sh_py_exists = os.path.exists(f"{dirpath}/{glue_file_name}")
    if tests_sh_exists and not tests_sh_py_exists:
        fail(
            f"System test directory `{testname}` is missing the "
            f"`{glue_file_name}` pytest glue file."
        )
