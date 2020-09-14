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

# Exit if program $1 is not found in PATH.
check_program() {
	if ! command -v "${1}" > /dev/null 2>&1; then
		echo "'${1}' not found in PATH" >&2
		exit 1
	fi
}

# Check that we were spawned with two arguments and that these arguments are two
# different directories.
check_args() {
	if [ ${#} -ne 2 ] || [ ! -d "${1}" ] || [ ! -d "${2}" ] || [ "${1}" = "${2}" ]; then
		echo "Usage:"
		echo ""
		echo "  ${0} <TESTDIR> <REFDIR>"
		echo ""
		echo "Generate API compatibility reports for BIND libraries."
		echo ""
		echo "  <TESTDIR> is a directory with current (new) BIND version"
		echo "  <REFDIR> is a directory with reference (old) BIND version"
		exit 1
	fi
}

check_args "${@}"
TESTBIND="${1}"
REFBIND="${2}"

# Ensure the required tools are available in PATH.
check_program abi-dumper
check_program abi-compliance-checker
check_program git
check_program w3m

# Find all libraries which have designated 'api' file and
# generate ABI dump file for them.
while read -r SO; do
	APIFILE="$(dirname "${SO}")/../api"
	APIFILE_DIR=$(dirname "${APIFILE}")
	GIT_HEAD_REV=$(git -C "${APIFILE_DIR}" rev-parse HEAD | cut -c 1-10)
	GIT_HEAD_UNIX_TIME=$(git -C "${APIFILE_DIR}" log -1 --format=%ct HEAD)
	# Get LIBINTERFACE, LIBREVISION, LIBAGE from the 'api' file.
	eval "$(grep -v "^#" "${APIFILE}" | tr -d " ")"
	VERSION="${LIBINTERFACE}.${LIBREVISION}.${LIBAGE}-${GIT_HEAD_UNIX_TIME}-${GIT_HEAD_REV}"
	abi-dumper "${SO}" -o abi-"$(basename "${SO}" .so)-${VERSION}".dump -lver "${VERSION}"
done < <(find "${TESTBIND}"/lib/*/.libs/ "${REFBIND}"/lib/*/.libs/ -name '*.so' ! -name '*-nosymtbl*')

# Generate HTML API compatibility reports for all libraries.
find . -maxdepth 1 -name 'abi-*.dump' | sort | while read -r OLD; read -r NEW; do
	SONAME=${OLD/.\/abi-/}
	SONAME=${SONAME/-*/}
	if abi-compliance-checker -l "${SONAME}" -old "${OLD}" -new "${NEW}"; then
		REPORT_PREFIX="PASS"
	else
		echo "***** Compatibility problems detected"
		REPORT_PREFIX="WARN"
	fi
	OLD_REPORT_PATH="$(find "compat_reports/${SONAME}" -name '*.html')"
	NEW_REPORT_PATH="${REPORT_PREFIX}-${SONAME}.html"
	mv "${OLD_REPORT_PATH}" "${NEW_REPORT_PATH}"
	echo
done

# Generate TXT API compatibility reports from HTML reports for all BIND libraries.
echo "Generate TXT API compatibility reports from HTML reports for all BIND libraries:"
while read -r HTMLREPORT; do
	TXTREPORT="${HTMLREPORT/.html/.txt}"
	echo "  w3m: ${HTMLREPORT} -> ${TXTREPORT}"
	w3m -dump -cols 75 -O ascii -T text/html "${HTMLREPORT}" > "${TXTREPORT}"
done < <(find . -maxdepth 1 -name '*-lib*.html')
