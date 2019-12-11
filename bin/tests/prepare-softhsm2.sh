#!/bin/sh
if [ -n "${SOFTHSM2_CONF}" ] && command -v softhsm2-util >/dev/null; then
    SOFTHSM2_DIR=$(dirname "$SOFTHSM2_CONF")
    mkdir -p "${SOFTHSM2_DIR}/tokens"
    echo "directories.tokendir = ${SOFTHSM2_DIR}/tokens" > "${SOFTHSM2_CONF}"
    echo "objectstore.backend = file" >> "${SOFTHSM2_CONF}"
    echo "log.level = DEBUG" >> "${SOFTHSM2_CONF}"
    softhsm2-util --init-token --free --pin 0000 --so-pin 0000 --label "softhsm2";
fi
exit 0
