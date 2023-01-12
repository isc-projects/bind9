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
#
# FUTURE: Rewrite the individual port fixtures to re-use the `ports` fixture.


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
    import time

    # Silence warnings caused by passing a pytest fixture to another fixture.
    # pylint: disable=redefined-outer-name

    # ----------------------- Globals definition -----------------------------

    XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
    FILE_DIR = os.path.abspath(Path(__file__).parent)
    ENV_RE = re.compile("([^=]+)=(.*)")
    PORT_MIN = 5001
    PORT_MAX = 32767
    PORTS_PER_TEST = 20

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

    # --------------------------- Fixtures -----------------------------------

    @pytest.fixture(scope="session")
    def modules():
        """Sorted list of all modules. Used to determine port distribution."""
        mods = []
        for dirpath, _dirs, files in os.walk(os.getcwd()):
            for file in files:
                if file.startswith("tests_") and file.endswith(".py"):
                    mod = f"{dirpath}/{file}"
                    mods.append(mod)
        return sorted(mods)

    @pytest.fixture(scope="session")
    def module_base_ports(modules):
        """
        Dictionary containing assigned base port for every module.

        Note that this is a session-wide fixture. The port numbers are
        deterministically assigned before any testing starts. This fixture MUST
        return the same value when called again during the same test session.
        When running tests in parallel, this is exactly what happens - every
        worker thread will call this fixture to determine test ports.
        """
        port_min = PORT_MIN
        port_max = PORT_MAX - len(modules) * PORTS_PER_TEST
        if port_max < port_min:
            raise RuntimeError(
                "not enough ports to assign unique port set to each module"
            )

        # Rotate the base port value over time to detect possible test issues
        # with using random ports. This introduces a very slight race condition
        # risk. If this value changes between pytest invocation and spawning
        # worker threads, multiple tests may have same port values assigned. If
        # these tests are then executed simultaneously, the test results will
        # be misleading.
        base_port = int(time.time() // 3600) % (port_max - port_min)

        return {mod: base_port + i * PORTS_PER_TEST for i, mod in enumerate(modules)}

    @pytest.fixture(scope="module")
    def base_port(request, module_base_ports):
        """Start of the port range assigned to a particular test module."""
        port = module_base_ports[request.fspath]
        return port

    @pytest.fixture(scope="module")
    def ports(base_port):
        """Dictionary containing port names and their assigned values."""
        return {
            "PORT": str(base_port),
            "TLSPORT": str(base_port + 1),
            "HTTPPORT": str(base_port + 2),
            "HTTPSPORT": str(base_port + 3),
            "EXTRAPORT1": str(base_port + 4),
            "EXTRAPORT2": str(base_port + 5),
            "EXTRAPORT3": str(base_port + 6),
            "EXTRAPORT4": str(base_port + 7),
            "EXTRAPORT5": str(base_port + 8),
            "EXTRAPORT6": str(base_port + 9),
            "EXTRAPORT7": str(base_port + 10),
            "EXTRAPORT8": str(base_port + 11),
            "CONTROLPORT": str(base_port + 12),
        }

    @pytest.fixture(scope="module")
    def env(ports):
        """Dictionary containing environment variables for the test."""
        env = CONF_ENV.copy()
        env.update(ports)
        env["builddir"] = f"{env['TOP_BUILDDIR']}/bin/tests/system"
        env["srcdir"] = f"{env['TOP_SRCDIR']}/bin/tests/system"
        return env
