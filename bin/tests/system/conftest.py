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

import os
import pytest


# ======================= LEGACY=COMPATIBLE FIXTURES =========================
# The following fixtures are designed to work with both pytest system test
# runner and the legacy system test framework.


@pytest.fixture(scope="module")
def named_port():
    return int(os.environ.get("PORT", default=5300))


@pytest.fixture(scope="module")
def named_tlsport():
    return int(os.environ.get("TLSPORT", default=8853))


@pytest.fixture(scope="module")
def named_httpsport():
    return int(os.environ.get("HTTPSPORT", default=4443))


@pytest.fixture(scope="module")
def control_port():
    return int(os.environ.get("CONTROLPORT", default=9953))


# ======================= PYTEST SYSTEM TEST RUNNER ==========================
# From this point onward, any setting, fixtures or functions only apply to the
# new pytest runner. Ideally, these would be in a separate file. However, due
# to how pytest works and how it's used by the legacy runner, the best approach
# is to have everything in this file to avoid duplication and set the
# LEGACY_TEST_RUNNER if pytest is executed from the legacy framework.
#
# FUTURE: Once legacy runner is no longer supported, remove the env var and
# don't branch the code.

if os.getenv("LEGACY_TEST_RUNNER", "0") == "0":
    import logging
    from pathlib import Path
    import re
    import subprocess

    # ----------------------- Globals definition -----------------------------

    XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
    FILE_DIR = os.path.abspath(Path(__file__).parent)
    ENV_RE = re.compile("([^=]+)=(.*)")

    # ---------------------- Module initialization ---------------------------

    def parse_env(env_text):
        """Parse the POSIX env format into Python dictionary."""
        out = {}
        for line in env_text.splitlines():
            match = ENV_RE.match(line)
            if match:
                out[match.groups()[0]] = match.groups()[1]
        return out

    def get_env(cmd):
        try:
            proc = subprocess.run(
                [cmd],
                shell=True,
                check=True,
                cwd=FILE_DIR,
                stdout=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as exc:
            logging.error("failed to get shell env: %s", exc)
            raise exc
        env_text = proc.stdout.decode("utf-8")
        return parse_env(env_text)

    # Read common environment variables for running tests from conf.sh.
    # FUTURE: Remove conf.sh entirely and define all variables in pytest only.
    CONF_ENV = get_env(". ./conf.sh && env")
    os.environ.update(CONF_ENV)
    logging.debug("conf.sh env: %s", CONF_ENV)

    # --------------------------- pytest hooks -------------------------------

    def pytest_configure():
        # Ensure this hook only runs on the main pytest instance if xdist is
        # used to spawn other workers.
        if not XDIST_WORKER:
            logging.debug("compiling required files")
            env = os.environ.copy()
            env["TESTS"] = ""  # disable automake test framework - compile-only
            try:
                # FUTURE: Remove the need to run this compilation command
                # before executing tests. Currently it's only here to have
                # on-par functionality with the legacy test framework.
                proc = subprocess.run(
                    "make -e check",
                    shell=True,
                    check=True,
                    cwd=FILE_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                )
            except subprocess.CalledProcessError as exc:
                logging.debug(exc.stdout)
                logging.error("failed to compile test files: %s", exc)
                raise exc
            logging.debug(proc.stdout)
