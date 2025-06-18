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
CONTAINER_ID=$(docker create --interactive debian:bookworm)
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
		libjson-c-dev				\
		liblmdb-dev				\
		libmaxminddb-dev			\
		libnghttp2-dev				\
		libssl-dev				\
		libtool					\
		liburcu-dev				\
		libuv1-dev				\
		make					\
		meson					\
		pkg-config				\
		pkgdiff					\
		xz-utils				\
"

# Retrieve the release-ready BIND 9 tarball.
docker cp "${BIND_TARBALL}" "${CONTAINER_ID}:/usr/src"

BIND_VERSION=$(basename "${BIND_TARBALL}" | sed -E "s|bind-(.*)\.tar\.xz|\1|")
BIND_MINOR_VERSION=$(echo "${BIND_VERSION}" | sed -E "s/^9\.(.*)\..*$/\1/")

# Prepare a temporary "release" tarball from upstream BIND 9 project.
run_in_container "git -c advice.detachedHead=false clone --branch v${BIND_VERSION} --depth 1 https://${GITLAB_USER}:${GITLAB_TOKEN}@gitlab.isc.org/isc-private/bind9.git && \
	apt-get -y install --no-install-recommends python3-pip && \
	rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
	pip3 install -r https://gitlab.isc.org/isc-projects/bind9/-/raw/main/doc/arm/requirements.txt"

if [ "${BIND_MINOR_VERSION}" -ge 21 ]; then
  run_in_container "cd bind9 && \
	  meson setup build && \
	  meson dist -C build --no-tests && \
	  mv -v build/meson-dist/bind-${BIND_VERSION}.tar.xz ."
else
  run_in_container "cd bind9 && \
	  autoreconf -fi && \
	  ./configure --enable-umbrella && \
	  make -j && \
	  make dist"
fi

# Compare release-ready and custom tarballs; they are expected to be the same.
run_in_container "pkgdiff bind9/bind-${BIND_VERSION}.tar.xz bind-${BIND_VERSION}.tar.xz" || true

# Copy the pkgdiff report out of the container for inspection.
docker cp "${CONTAINER_ID}:/usr/src/pkgdiff_reports/bind/" "pkgdiff_bind_${BIND_VERSION}_report"
echo "pkgdiff report ready for inspection in 'pkgdiff_bind_${BIND_VERSION}_report'."
