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

if [ -z "$MESON_DIST_ROOT" ] || [ -z "$MESON_SOURCE_ROOT" ]; then
  echo "meson-dist-package.sh must be run inside meson dist!"
  exit 1
fi

generate_man_pages() {
  export MESON_PROJECT_VERSION=$1

  export SPHINX_BUILD=$2

  if [ -d "${MESON_BUILD_ROOT}/dist-man" ]; then
    rm -r "${MESON_BUILD_ROOT}/dist-man"
  fi

  $SPHINX_BUILD \
    -W \
    -a \
    -n \
    -q \
    -b man \
    -D "release=${MESON_PROJECT_VERSION}" \
    -D "version=${MESON_PROJECT_VERSION}" \
    -D "today=@RELEASE_DATE@" \
    -d "${MESON_BUILD_ROOT}/dist-man-buildroot" \
    -c "${MESON_SOURCE_ROOT}/doc/man" \
    "${MESON_SOURCE_ROOT}/doc/man" \
    "${MESON_BUILD_ROOT}/dist-man"

  for man in ${MESON_BUILD_ROOT}/dist-man/man1/*; do
    [ -f "${man}" ] || continue
    cp $man "${MESON_DIST_ROOT}/doc/man/${man##*/}.in"
  done

  for man in ${MESON_BUILD_ROOT}/dist-man/man5/*; do
    [ -f "${man}" ] || continue
    cp $man "${MESON_DIST_ROOT}/doc/man/${man##*/}.in"
  done

  for man in ${MESON_BUILD_ROOT}/dist-man/man8/*; do
    [ -f "${man}" ] || continue
    cp $man "${MESON_DIST_ROOT}/doc/man/${man##*/}.in"
  done
}

case $1 in
  "srcid")
    echo $2 >$MESON_DIST_ROOT/srcid
    ;;
  "manual")
    generate_man_pages $2 $3
    ;;
  *)
    echo "invalid usage"
    exit 1
    ;;
esac
