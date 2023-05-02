#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e
set -o nounset

print_usage_and_exit() {
	echo
	echo "Usage: GITLAB_USER=<your_gitlab_username> GITLAB_TOKEN=<your_gitlab_token> ${0} /path/to/bind-9.x.y.tar.xz" >&2
	exit 1
}

BIND_TARBALL="${1:-}"
if [ ! -f "${BIND_TARBALL}" ]; then
	echo "ERROR: path to BIND 9 tarball either not provided or the file does not exist." >&2
	print_usage_and_exit
fi

GITLAB_USER=${GITLAB_USER:-}
GITLAB_TOKEN=${GITLAB_TOKEN:-}
if [ -z "${GITLAB_USER}" ] || [ -z "${GITLAB_TOKEN}" ]; then
	echo "ERROR: GITLAB_USER and GITLAB_TOKEN environmental variables are not set." >&2
	print_usage_and_exit
fi

# Create the container to work in.
CONTAINER_ID=$(docker create --interactive debian:bullseye)
trap "docker container rm -f \${CONTAINER_ID} >/dev/null" EXIT
docker start "${CONTAINER_ID}"

run_in_container() {
	docker exec --workdir /usr/src "${CONTAINER_ID}" /bin/sh -c "$@"
}

# Pull build requirements.
run_in_container "apt-get update &&			\
	apt-get -y install --no-install-recommends	\
		automake				\
		ca-certificates				\
		git					\
		libcap2-dev				\
		libjemalloc-dev				\
		liblmdb-dev				\
		libmaxminddb-dev			\
		libnghttp2-dev				\
		libssl-dev				\
		libtool					\
		liburcu-dev				\
		libuv1-dev				\
		make					\
		pkg-config				\
		pkgdiff					\
		xz-utils				\
"

run_in_container "apt-get -y install --no-install-recommends python3-pip && \
	rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
	pip3 install docutils==0.18.1 sphinx-rtd-theme==1.2.0 sphinx==6.1.3"

# Retrieve the release-ready BIND 9 tarball.
docker cp "${BIND_TARBALL}" "${CONTAINER_ID}:/usr/src"

BIND_VERSION=$(basename "${BIND_TARBALL}" | sed -E "s|bind-(.*)\.tar\.xz|\1|")
BIND_DIRECTORY="bind-${BIND_VERSION}"

# Prepare a temporary "release" tarball from upstream BIND 9 project.
run_in_container "git -c advice.detachedHead=false clone --branch v${BIND_VERSION} --depth 1 https://${GITLAB_USER}:${GITLAB_TOKEN}@gitlab.isc.org/isc-private/bind9.git && \
	cd bind9 && \
	if [ $(echo "${BIND_VERSION}" | cut -b 1-5) = 9.16. ]; then \
		git archive --prefix=${BIND_DIRECTORY}/ --output=${BIND_DIRECTORY}.tar HEAD && \
		mkdir ${BIND_DIRECTORY} && \
		echo SRCID=\$(git rev-list --max-count=1 HEAD | cut -b1-7) > ${BIND_DIRECTORY}/srcid && \
		tar --append --file=${BIND_DIRECTORY}.tar ${BIND_DIRECTORY}/srcid && \
		sphinx-build -b man -d ${BIND_DIRECTORY}/tmp/.doctrees/ -W -a -v -c doc/man/ -D version=@BIND9_VERSION@ -D today=@RELEASE_DATE@ -D release=@BIND9_VERSIONSTRING@ doc/man ${BIND_DIRECTORY}/doc/man && \
		rm -rf ${BIND_DIRECTORY}/tmp/.doctrees/ && \
		for man in ${BIND_DIRECTORY}/doc/man/*; do mv \${man} \${man}in; done && \
		tar --append --file=${BIND_DIRECTORY}.tar ${BIND_DIRECTORY}/doc/man/*in && \
		xz ${BIND_DIRECTORY}.tar; \
	else \
		autoreconf -fi && \
		./configure --enable-umbrella && \
		make -j && \
		make dist; \
	fi"

# Compare release-ready and custom tarballs; they are expected to be the same.
run_in_container "pkgdiff bind9/bind-${BIND_VERSION}.tar.xz bind-${BIND_VERSION}.tar.xz" || true

# Copy the pkgdiff report out of the container for inspection.
docker cp "${CONTAINER_ID}:/usr/src/pkgdiff_reports/bind/" "pkgdiff_bind_${BIND_VERSION}_report"
echo "pkgdiff report ready for inspection in 'pkgdiff_bind_${BIND_VERSION}_report'."
