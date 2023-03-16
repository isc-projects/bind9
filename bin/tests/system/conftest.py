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
    from functools import partial
    import logging
    from pathlib import Path
    import re
    import shutil
    import subprocess
    import tempfile
    import time
    from typing import Any, Dict, List, Optional

    # Silence warnings caused by passing a pytest fixture to another fixture.
    # pylint: disable=redefined-outer-name

    # ----------------- Older pytest / xdist compatibility -------------------
    # As of 2023-01-11, the minimal supported pytest / xdist versions are
    # determined by what is available in EL8/EPEL8:
    # - pytest 3.4.2
    # - pytest-xdist 1.24.1
    _pytest_ver = pytest.__version__.split(".")
    _pytest_major_ver = int(_pytest_ver[0])
    if _pytest_major_ver < 7:
        # pytest.Stash/pytest.StashKey mechanism has been added in 7.0.0
        # for older versions, use regular dictionary with string keys instead
        FIXTURE_OK = "fixture_ok"  # type: Any
    else:
        FIXTURE_OK = pytest.StashKey[bool]()  # pylint: disable=no-member

    # ----------------------- Globals definition -----------------------------

    LOG_FORMAT = "%(asctime)s %(levelname)7s:%(name)s  %(message)s"
    XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
    FILE_DIR = os.path.abspath(Path(__file__).parent)
    ENV_RE = re.compile("([^=]+)=(.*)")
    PORT_MIN = 5001
    PORT_MAX = 32767
    PORTS_PER_TEST = 20

    # ---------------------- Module initialization ---------------------------

    def avoid_duplicated_logs():
        """
        Remove direct root logger output to file descriptors.
        This default is causing duplicates because all our messages go through
        regular logging as well and are thus displayed twice.
        """
        todel = []
        for handler in logging.root.handlers:
            if handler.__class__ == logging.StreamHandler:
                # Beware: As for pytest 7.2.2, LiveLogging and LogCapture
                # handlers inherit from logging.StreamHandler
                todel.append(handler)
        for handler in todel:
            logging.root.handlers.remove(handler)

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

    def pytest_addoption(parser):
        parser.addoption(
            "--noclean",
            action="store_true",
            default=False,
            help="don't remove the temporary test directories with artifacts",
        )

    def pytest_configure(config):
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

            if config.pluginmanager.has_plugin("xdist") and config.option.numprocesses:
                # system tests depend on module scope for setup & teardown
                # enforce use "loadscope" scheduler or disable paralelism
                try:
                    import xdist.scheduler.loadscope  # pylint: disable=unused-import
                except ImportError:
                    logging.debug(
                        "xdist is too old and does not have "
                        "scheduler.loadscope, disabling parallelism"
                    )
                    config.option.dist = "no"
                else:
                    config.option.dist = "loadscope"

    def pytest_ignore_collect(path):
        # System tests are executed in temporary directories inside
        # bin/tests/system. These temporary directories contain all files
        # needed for the system tests - including tests_*.py files. Make sure to
        # ignore these during test collection phase. Otherwise, test artifacts
        # from previous runs could mess with the runner.
        return "_tmp_" in str(path)

    @pytest.hookimpl(tryfirst=True, hookwrapper=True)
    def pytest_runtest_makereport(item):
        """Hook that is used to expose test results to session (for use in fixtures)."""
        # execute all other hooks to obtain the report object
        outcome = yield
        report = outcome.get_result()

        # Set the test outcome in session, so we can access it from module-level
        # fixture using nodeid. Note that this hook is called three times: for
        # setup, call and teardown. We only care about the overall result so we
        # merge the results together and preserve the information whether a test
        # passed.
        test_results = {}
        try:
            test_results = getattr(item.session, "test_results")
        except AttributeError:
            setattr(item.session, "test_results", test_results)
        node_result = test_results.get(item.nodeid)
        if node_result is None or report.outcome != "passed":
            test_results[item.nodeid] = report.outcome

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

    @pytest.fixture(scope="module")
    def system_test_name(request):
        """Name of the system test directory."""
        path = Path(request.fspath)
        return path.parent.name

    @pytest.fixture(scope="module")
    def logger(system_test_name):
        """Logging facility specific to this test."""
        avoid_duplicated_logs()
        return logging.getLogger(system_test_name)

    @pytest.fixture(scope="module")
    def system_test_dir(request, env, system_test_name, logger):
        """
        Temporary directory for executing the test.

        This fixture is responsible for creating (and potentially removing) a
        copy of the system test directory which is used as a temporary
        directory for the test execution.

        FUTURE: This removes the need to have clean.sh scripts.
        """

        def get_test_result():
            """Aggregate test results from all individual tests from this module
            into a single result: failed > skipped > passed."""
            test_results = {
                node.nodeid: request.session.test_results[node.nodeid]
                for node in request.node.collect()
                if node.nodeid in request.session.test_results
            }
            logger.debug(test_results)
            assert len(test_results)
            failed = any(res == "failed" for res in test_results.values())
            skipped = any(res == "skipped" for res in test_results.values())
            if failed:
                return "failed"
            if skipped:
                return "skipped"
            assert all(res == "passed" for res in test_results.values())
            return "passed"

        # Create a temporary directory with a copy of the original system test dir contents
        system_test_root = Path(f"{env['TOP_BUILDDIR']}/bin/tests/system")
        testdir = Path(
            tempfile.mkdtemp(prefix=f"{system_test_name}_tmp_", dir=system_test_root)
        )
        shutil.rmtree(testdir)
        shutil.copytree(system_test_root / system_test_name, testdir)

        # Configure logger to write to a file inside the temporary test directory
        logger.handlers.clear()
        logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(testdir / "pytest.log.txt", mode="w")
        formatter = logging.Formatter(LOG_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # System tests are meant to be executed from their directory - switch to it.
        old_cwd = os.getcwd()
        os.chdir(testdir)
        logger.info("switching to tmpdir: %s", testdir)
        try:
            yield testdir  # other fixtures / tests will execute here
        finally:
            os.chdir(old_cwd)
            logger.debug("changed workdir to: %s", old_cwd)

            result = get_test_result()

            # Clean temporary dir unless it should be kept
            if request.config.getoption("--noclean"):
                logger.debug("--noclean requested, keeping temporary directory")
            elif result == "failed":
                logger.debug("test failure detected, keeping temporary directory")
            elif not request.node.stash[FIXTURE_OK]:
                logger.debug(
                    "test setup/teardown issue detected, keeping temporary directory"
                )
            else:
                logger.debug("deleting temporary directory")
                shutil.rmtree(testdir)

    def _run_script(  # pylint: disable=too-many-arguments
        env,
        logger,
        system_test_dir: Path,
        interpreter: str,
        script: str,
        args: Optional[List[str]] = None,
    ):
        """Helper function for the shell / perl script invocations (through fixtures below)."""
        if args is None:
            args = []
        path = Path(script)
        if not path.is_absolute():
            # make sure relative paths are always relative to system_dir
            path = system_test_dir.parent / path
        script = str(path)
        cwd = os.getcwd()
        if not path.exists():
            raise FileNotFoundError(f"script {script} not found in {cwd}")
        logger.debug("running script: %s %s %s", interpreter, script, " ".join(args))
        logger.debug("  workdir: %s", cwd)
        returncode = 1

        cmd = [interpreter, script] + args
        with subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True,
            errors="backslashreplace",
        ) as proc:
            if proc.stdout:
                for line in proc.stdout:
                    logger.info("    %s", line.rstrip("\n"))
            proc.communicate()
            returncode = proc.returncode
            if returncode:
                raise subprocess.CalledProcessError(returncode, cmd)
            logger.debug("  exited with %d", returncode)

    @pytest.fixture(scope="module")
    def shell(env, system_test_dir, logger):
        """Function to call a shell script with arguments."""
        return partial(_run_script, env, logger, system_test_dir, env["SHELL"])

    @pytest.fixture(scope="module")
    def perl(env, system_test_dir, logger):
        """Function to call a perl script with arguments."""
        return partial(_run_script, env, logger, system_test_dir, env["PERL"])

    @pytest.fixture(scope="module")
    def run_tests_sh(system_test_dir, shell):
        """Utility function to execute tests.sh as a python test."""

        def run_tests():
            shell(f"{system_test_dir}/tests.sh")

        return run_tests

    @pytest.fixture(scope="module", autouse=True)
    def system_test(  # pylint: disable=too-many-arguments,too-many-statements
        request,
        env: Dict[str, str],
        logger,
        system_test_dir,
        shell,
        perl,
    ):
        """
        Driver of the test setup/teardown process. Used automatically for every test module.

        This is the most important one-fixture-to-rule-them-all. Note the
        autouse=True which causes this fixture to be loaded by every test
        module without the need to explicitly specify it.

        When this fixture is used, it utilizes other fixtures, such as
        system_test_dir, which handles the creation of the temporary test
        directory.

        Afterwards, it checks the test environment and takes care of starting
        the servers. When everything is ready, that's when the actual tests are
        executed. Once that is done, this fixture stops the servers and checks
        for any artifacts indicating an issue (e.g. coredumps).

        Finally, when this fixture reaches an end (or encounters an exception,
        which may be caused by fail/skip invocations), any fixtures which is
        used by this one are finalized - e.g. system_test_dir performs final
        checks and cleans up the temporary test directory.
        """

        def check_net_interfaces():
            try:
                perl("testsock.pl", ["-p", env["PORT"]])
            except subprocess.CalledProcessError as exc:
                logger.error("testsock.pl: exited with code %d", exc.returncode)
                pytest.skip("Network interface aliases not set up.")

        def check_prerequisites():
            try:
                shell(f"{system_test_dir}/prereq.sh")
            except FileNotFoundError:
                pass  # prereq.sh is optional
            except subprocess.CalledProcessError:
                pytest.skip("Prerequisites missing.")

        def setup_test():
            try:
                shell(f"{system_test_dir}/setup.sh")
            except FileNotFoundError:
                pass  # setup.sh is optional
            except subprocess.CalledProcessError as exc:
                logger.error("Failed to run test setup")
                pytest.fail(f"setup.sh exited with {exc.returncode}")

        def start_servers():
            try:
                perl("start.pl", ["--port", env["PORT"], system_test_dir.name])
            except subprocess.CalledProcessError as exc:
                logger.error("Failed to start servers")
                pytest.fail(f"start.pl exited with {exc.returncode}")

        def stop_servers():
            try:
                perl("stop.pl", [system_test_dir.name])
            except subprocess.CalledProcessError as exc:
                logger.error("Failed to stop servers")
                pytest.fail(f"stop.pl exited with {exc.returncode}")

        def get_core_dumps():
            try:
                shell("get_core_dumps.sh", [system_test_dir.name])
            except subprocess.CalledProcessError as exc:
                logger.error("Found core dumps")
                pytest.fail(f"get_core_dumps.sh exited with {exc.returncode}")

        os.environ.update(env)  # Ensure pytests have the same env vars as shell tests.
        logger.info(f"test started: {request.node.name}")
        port = int(env["PORT"])
        logger.info("using port range: <%d, %d>", port, port + PORTS_PER_TEST - 1)

        if not hasattr(request.node, "stash"):  # compatibility with pytest<7.0.0
            request.node.stash = {}  # use regular dict instead of pytest.Stash
        request.node.stash[FIXTURE_OK] = True

        # Perform checks which may skip this test.
        check_net_interfaces()
        check_prerequisites()

        # Store the fact that this fixture hasn't successfully finished yet.
        # This is checked before temporary directory teardown to decide whether
        # it's okay to remove the directory.
        request.node.stash[FIXTURE_OK] = False

        setup_test()
        try:
            start_servers()
            logger.debug("executing test(s)")
            yield
        finally:
            logger.debug("test(s) finished")
            stop_servers()
            get_core_dumps()
            request.node.stash[FIXTURE_OK] = True
