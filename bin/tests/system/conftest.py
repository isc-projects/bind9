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

from functools import partial
import filecmp
import os
from pathlib import Path
from re import compile as Re
import shutil
import subprocess
import tempfile
import time
from typing import Dict, List, Optional
import sys

import pytest

pytest.register_assert_rewrite("isctest")

import isctest

# Silence warnings caused by passing a pytest fixture to another fixture.
# pylint: disable=redefined-outer-name

if sys.version_info[1] < 10:
    raise RuntimeError("Python 3.10 or newer is required to run system tests.")

isctest.log.init_conftest_logger()
isctest.log.avoid_duplicated_logs()

# ----------------------- Globals definition -----------------------------

XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
FILE_DIR = os.path.abspath(Path(__file__).parent)
ENV_RE = Re(b"([^=]+)=(.*)")
PORT_MIN = 5001
PORT_MAX = 32767
PORTS_PER_TEST = 20
PRIORITY_TESTS = [
    # Tests that are scheduled first. Speeds up parallel execution.
    "dupsigs/",
    "rpz/",
    "rpzrecurse/",
    "serve-stale/",
    "timeouts/",
    "upforwd/",
]
PRIORITY_TESTS_RE = Re("|".join(PRIORITY_TESTS))
SYSTEM_TEST_DIR_GIT_PATH = "bin/tests/system"
SYSTEM_TEST_NAME_RE = Re(f"{SYSTEM_TEST_DIR_GIT_PATH}" + r"/([^/]+)")
SYMLINK_REPLACEMENT_RE = Re(r"/tests_(.*)\.py")

# ---------------------- Module initialization ---------------------------


def parse_env(env_bytes):
    """Parse the POSIX env format into Python dictionary."""
    out = {}
    for line in env_bytes.splitlines():
        match = ENV_RE.match(line)
        if match:
            # EL8+ workaround for https://access.redhat.com/solutions/6994985
            # FUTURE: can be removed when we no longer need to parse env vars
            if match.groups()[0] in [b"which_declare", b"BASH_FUNC_which%%"]:
                continue
            out[match.groups()[0]] = match.groups()[1]
    return out


def get_env_bytes(cmd):
    try:
        proc = subprocess.run(
            [cmd],
            shell=True,
            check=True,
            cwd=FILE_DIR,
            stdout=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        isctest.log.error("failed to get shell env: %s", exc)
        raise exc
    env_bytes = proc.stdout
    return parse_env(env_bytes)


# Read common environment variables for running tests from conf.sh.
# FUTURE: Remove conf.sh entirely and define all variables in pytest only.
CONF_ENV = get_env_bytes(". ./conf.sh && env")
os.environb.update(CONF_ENV)
isctest.log.debug("variables in env: %s", ", ".join([str(key) for key in CONF_ENV]))

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
        if config.pluginmanager.has_plugin("xdist") and config.option.numprocesses:
            # system tests depend on module scope for setup & teardown
            # enforce use "loadscope" scheduler or disable paralelism
            try:
                import xdist.scheduler.loadscope  # pylint: disable=unused-import
            except ImportError:
                isctest.log.debug(
                    "xdist is too old and does not have "
                    "scheduler.loadscope, disabling parallelism"
                )
                config.option.dist = "no"
            else:
                config.option.dist = "loadscope"


def pytest_ignore_collect(collection_path):
    # System tests are executed in temporary directories inside
    # bin/tests/system. These temporary directories contain all files
    # needed for the system tests - including tests_*.py files. Make sure to
    # ignore these during test collection phase. Otherwise, test artifacts
    # from previous runs could mess with the runner. Also ignore the
    # convenience symlinks to those test directories. In both of those
    # cases, the system test name (directory) contains a hyphen, which
    # is otherwise and invalid character for a system test name.
    match = SYSTEM_TEST_NAME_RE.search(str(collection_path))
    if match is None:
        isctest.log.warning("unexpected test path: %s (ignored)", collection_path)
        return True
    system_test_name = match.groups()[0]
    return "-" in system_test_name


def pytest_collection_modifyitems(items):
    """Schedule long-running tests first to get more benefit from parallelism."""
    priority = []
    other = []
    for item in items:
        if PRIORITY_TESTS_RE.search(item.nodeid):
            priority.append(item)
        else:
            other.append(item)
    items[:] = priority + other


class NodeResult:
    def __init__(self, report=None):
        self._outcomes = {}
        self.messages = {}
        if report is not None:
            self.update(report)

    def update(self, report):
        # Allow the same nodeid/when to be overriden. This only happens when
        # the test is re-run with flaky plugin. In that case, we want the
        # latest result to override any previous results.
        key = (report.nodeid, report.when)
        self._outcomes[key] = report.outcome
        self.messages[key] = report.longreprtext

    @property
    def outcome(self):
        for outcome in self._outcomes.values():
            if outcome != "passed":
                return outcome
        return "passed"


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
    node_result = test_results.setdefault(item.nodeid, NodeResult())
    node_result.update(report)


# --------------------------- Fixtures -----------------------------------


@pytest.fixture(scope="session")
def modules():
    """
    Sorted list of ALL modules.

    The list includes even test modules that are not tested in the current
    session. It is used to determine port distribution. Using a complete
    list of all possible test modules allows independent concurrent pytest
    invocations.
    """
    mods = []
    for dirpath, _dirs, files in os.walk(FILE_DIR):
        for file in files:
            if file.startswith("tests_") and file.endswith(".py"):
                mod = f"{dirpath}/{file}"
                if not pytest_ignore_collect(mod):
                    mods.append(mod)
    return sorted(mods)


@pytest.fixture(scope="session")
def module_base_ports(modules):
    """
    Dictionary containing assigned base port for every module.

    The port numbers are deterministically assigned before any testing
    starts. This fixture MUST return the same value when called again
    during the same test session. When running tests in parallel, this is
    exactly what happens - every worker thread will call this fixture to
    determine test ports.
    """
    port_min = PORT_MIN
    port_max = PORT_MAX - len(modules) * PORTS_PER_TEST
    if port_max < port_min:
        raise RuntimeError("not enough ports to assign unique port set to each module")

    # Rotate the base port value over time to detect possible test issues
    # with using random ports. This introduces a very slight race condition
    # risk. If this value changes between pytest invocation and spawning
    # worker threads, multiple tests may have same port values assigned. If
    # these tests are then executed simultaneously, the test results will
    # be misleading.
    base_port = int(time.time() // 3600) % (port_max - port_min) + port_min

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
        "PORT": base_port,
        "TLSPORT": base_port + 1,
        "HTTPPORT": base_port + 2,
        "HTTPSPORT": base_port + 3,
        "EXTRAPORT1": base_port + 4,
        "EXTRAPORT2": base_port + 5,
        "EXTRAPORT3": base_port + 6,
        "EXTRAPORT4": base_port + 7,
        "EXTRAPORT5": base_port + 8,
        "EXTRAPORT6": base_port + 9,
        "EXTRAPORT7": base_port + 10,
        "EXTRAPORT8": base_port + 11,
        "CONTROLPORT": base_port + 12,
    }


@pytest.fixture(scope="module")
def named_port(ports):
    return ports["PORT"]


@pytest.fixture(scope="module")
def named_tlsport(ports):
    return ports["TLSPORT"]


@pytest.fixture(scope="module")
def named_httpsport(ports):
    return ports["HTTPSPORT"]


@pytest.fixture(scope="module")
def control_port(ports):
    return ports["CONTROLPORT"]


@pytest.fixture(scope="module")
def env(ports):
    """Dictionary containing environment variables for the test."""
    env = os.environ.copy()
    for portname, portnum in ports.items():
        env[portname] = str(portnum)
    env["builddir"] = f"{env['TOP_BUILDDIR']}/{SYSTEM_TEST_DIR_GIT_PATH}"
    env["srcdir"] = f"{env['TOP_SRCDIR']}/{SYSTEM_TEST_DIR_GIT_PATH}"
    env["HYPOTHESIS_STORAGE_DIRECTORY"] = (
        f"{env['TOP_BUILDDIR']}/{SYSTEM_TEST_DIR_GIT_PATH}/.hypothesis"
    )
    return env


@pytest.fixture(scope="module")
def system_test_name(request):
    """Name of the system test directory."""
    path = Path(request.fspath)
    return path.parent.name


@pytest.fixture(autouse=True)
def wait_for_zones_loaded(request, servers):
    """Wait for all zones to be loaded by specified named instances."""
    instances = request.node.get_closest_marker("requires_zones_loaded")
    if not instances:
        return

    for instance in instances.args:
        with servers[instance].watch_log_from_start() as watcher:
            watcher.wait_for_line("all zones loaded")


@pytest.fixture(autouse=True)
def logger(request, system_test_name):
    """Sets up logging facility specific to a particular test."""
    isctest.log.init_test_logger(system_test_name, request.node.name)
    yield
    isctest.log.deinit_test_logger()


@pytest.fixture(scope="module")
def expected_artifacts(request):
    common_artifacts = [
        ".libs/*",  # possible build artifacts, see GL #5055
        "ns*/named.conf",
        "ns*/named.lock",
        "ns*/named.memstats",
        "ns*/named.run",
        "ns*/named.run.prev",
        "core.[0-9]*-backtrace.txt",
        "core.[0-9]*.gz",
        "pytest.log.txt",
        "tsan.*.[0-9]*",
    ]

    if "USE_RR" in os.environ:
        common_artifacts += [
            "ns*/cpu_lock",
            "ns*/latest-trace",
            "ns*/named-[0-9]*",
        ]

    try:
        test_specific_artifacts = request.node.get_closest_marker("extra_artifacts")
    except AttributeError:
        return None

    if test_specific_artifacts:
        return common_artifacts + test_specific_artifacts.args[0]

    return None


@pytest.fixture(scope="module")
def system_test_dir(request, env, system_test_name, expected_artifacts):
    """
    Temporary directory for executing the test.

    This fixture is responsible for creating (and potentially removing) a
    copy of the system test directory which is used as a temporary
    directory for the test execution.
    """

    def get_test_result():
        """Aggregate test results from all individual tests from this module
        into a single result: failed > skipped > passed."""
        try:
            all_test_results = request.session.test_results
        except AttributeError:
            # This may happen if pytest execution is interrupted and
            # pytest_runtest_makereport() is never called.
            isctest.log.debug("can't obtain test results, test run was interrupted")
            return "error"
        test_results = {
            node.nodeid: all_test_results[node.nodeid]
            for node in request.node.collect()
            if node.nodeid in all_test_results
        }
        assert len(test_results)
        for node, result in test_results.items():
            message = f"{result.outcome.upper()} {node}"
            nonempty_extra = [msg for msg in result.messages.values() if msg.strip()]
            if nonempty_extra:
                message += "\n"
                message += "\n\n".join(nonempty_extra)
            isctest.log.debug(message)
        failed = any(res.outcome == "failed" for res in test_results.values())
        skipped = any(res.outcome == "skipped" for res in test_results.values())
        if failed:
            return "failed"
        if skipped:
            return "skipped"
        assert all(res.outcome == "passed" for res in test_results.values())
        return "passed"

    def check_artifacts(source_dir, run_dir):
        def check_artifacts_recursive(dcmp):
            def artifact_expected(path, expected):
                for glob in expected:
                    if path.match(glob):
                        return True
                return False

            # test must not remove any Git-tracked file, ignore libtool and gcov artifacts
            for name in dcmp.left_only:
                path = Path(name)
                assert path.name.startswith("lt-") or path.suffix == ".gcda"
            assert not dcmp.diff_files, "test must not modify any Git-tracked file"

            dir_path = Path(dcmp.left).relative_to(source_dir)
            for name in dcmp.right_only:
                file = dir_path / Path(name)
                if not artifact_expected(file, expected_artifacts):
                    unexpected_files.append(str(file))
            for subdir in dcmp.subdirs.values():
                check_artifacts_recursive(subdir)

        if expected_artifacts is None:  # skip the check if artifact list is unavailable
            return

        unexpected_files = []
        dcmp = filecmp.dircmp(source_dir, run_dir)
        check_artifacts_recursive(dcmp)

        assert (
            not unexpected_files
        ), f"Unexpected files found in test directory: {unexpected_files}"

    # Create a temporary directory with a copy of the original system test dir contents
    system_test_root = Path(
        f"{env['TOP_BUILDDIR']}/{SYSTEM_TEST_DIR_GIT_PATH}"
    ).resolve()
    testdir = Path(
        tempfile.mkdtemp(prefix=f"{system_test_name}-tmp-", dir=system_test_root)
    )
    shutil.rmtree(testdir)
    shutil.copytree(system_test_root / system_test_name, testdir)

    # Create a convenience symlink with a stable and predictable name
    module_name = SYMLINK_REPLACEMENT_RE.sub(r"-\1", str(request.node.path))
    symlink_dst = system_test_root / module_name
    symlink_dst.unlink(missing_ok=True)
    symlink_dst.symlink_to(os.path.relpath(testdir, start=system_test_root))

    isctest.log.init_module_logger(system_test_name, testdir)

    # System tests are meant to be executed from their directory - switch to it.
    old_cwd = os.getcwd()
    os.chdir(testdir)
    isctest.log.info("switching to tmpdir: %s", testdir)
    try:
        yield testdir  # other fixtures / tests will execute here
    finally:
        os.chdir(old_cwd)
        isctest.log.debug("changed workdir to: %s", old_cwd)

        result = get_test_result()

        if result == "passed":
            check_artifacts(system_test_root / system_test_name, testdir)

        # Clean temporary dir unless it should be kept
        keep = False
        if request.config.getoption("--noclean"):
            isctest.log.debug(
                "--noclean requested, keeping temporary directory %s", testdir
            )
            keep = True
        elif result == "failed":
            isctest.log.debug(
                "test failure detected, keeping temporary directory %s", testdir
            )
            keep = True
        elif not request.node.stash["fixture_ok"]:
            isctest.log.debug(
                "test setup/teardown issue detected, keeping temporary directory %s",
                testdir,
            )
            keep = True

        if keep:
            isctest.log.info(
                "test artifacts in: %s", symlink_dst.relative_to(system_test_root)
            )
        else:
            isctest.log.debug("deleting temporary directory")

        isctest.log.deinit_module_logger()
        if not keep:
            shutil.rmtree(testdir)
            symlink_dst.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def templates(system_test_dir: Path, env):
    return isctest.template.TemplateEngine(system_test_dir, env)


def _run_script(
    env,
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
    isctest.log.debug("running script: %s %s %s", interpreter, script, " ".join(args))
    isctest.log.debug("  workdir: %s", cwd)
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
                isctest.log.info("    %s", line.rstrip("\n"))
        proc.communicate()
        returncode = proc.returncode
        if returncode:
            raise subprocess.CalledProcessError(returncode, cmd)
        isctest.log.debug("  exited with %d", returncode)


@pytest.fixture(scope="module")
def shell(env, system_test_dir):
    """Function to call a shell script with arguments."""
    return partial(_run_script, env, system_test_dir, env["SHELL"])


@pytest.fixture(scope="module")
def perl(env, system_test_dir):
    """Function to call a perl script with arguments."""
    return partial(_run_script, env, system_test_dir, env["PERL"])


@pytest.fixture(scope="module")
def run_tests_sh(system_test_dir, shell):
    """Utility function to execute tests.sh as a python test."""

    def run_tests():
        shell(f"{system_test_dir}/tests.sh")

    return run_tests


@pytest.fixture(scope="module", autouse=True)
def system_test(
    request,
    env: Dict[str, str],
    system_test_dir,
    templates,
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
            isctest.log.error("testsock.pl: exited with code %d", exc.returncode)
            pytest.skip("Network interface aliases not set up.")

    def check_prerequisites():
        try:
            shell(f"{system_test_dir}/prereq.sh")
        except FileNotFoundError:
            pass  # prereq.sh is optional
        except subprocess.CalledProcessError:
            pytest.skip("Prerequisites missing.")

    def setup_test():
        template_data = None
        bootstrap_fn = getattr(request.module, "bootstrap", None)
        if bootstrap_fn:
            isctest.log.debug("Running test bootstrap()")
            try:
                template_data = bootstrap_fn()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                isctest.log.error("Failed to run test bootstrap()")
                kind = type(exc).__name__
                pytest.fail(f"bootstrap() failed with {kind}")

        templates.render_auto(template_data)

        setup_sh_path = f"{system_test_dir}/setup.sh"
        if os.path.exists(setup_sh_path):
            try:
                shell(f"{system_test_dir}/setup.sh")
            except subprocess.CalledProcessError as exc:
                isctest.log.error("Failed to run test setup.sh")
                pytest.fail(f"setup.sh exited with {exc.returncode}")

    def start_servers():
        try:
            perl("start.pl", ["--port", env["PORT"], system_test_dir.name])
        except subprocess.CalledProcessError as exc:
            isctest.log.error("Failed to start servers")
            pytest.fail(f"start.pl exited with {exc.returncode}")

    def stop_servers():
        try:
            perl("stop.pl", [system_test_dir.name])
        except subprocess.CalledProcessError as exc:
            isctest.log.error("Failed to stop servers")
            get_core_dumps()
            pytest.fail(f"stop.pl exited with {exc.returncode}")

    def get_core_dumps():
        try:
            shell("get_core_dumps.sh", [system_test_dir.name])
        except subprocess.CalledProcessError as exc:
            isctest.log.error("Found core dumps or sanitizer reports")
            pytest.fail(f"get_core_dumps.sh exited with {exc.returncode}")

    os.environ.update(env)  # Ensure pytests have the same env vars as shell tests.
    isctest.log.info(f"test started: {request.node.path}")
    port = int(env["PORT"])
    isctest.log.info("using port range: <%d, %d>", port, port + PORTS_PER_TEST - 1)

    request.node.stash["fixture_ok"] = True

    # Perform checks which may skip this test.
    check_net_interfaces()
    check_prerequisites()

    # Store the fact that this fixture hasn't successfully finished yet.
    # This is checked before temporary directory teardown to decide whether
    # it's okay to remove the directory.
    request.node.stash["fixture_ok"] = False

    setup_test()
    try:
        start_servers()
        isctest.log.debug("executing test(s)")
        yield
    finally:
        isctest.log.debug("test(s) finished")
        stop_servers()
        get_core_dumps()
        request.node.stash["fixture_ok"] = True


@pytest.fixture(scope="module")
def servers(ports, system_test_dir):
    instances = {}
    for entry in system_test_dir.rglob("*"):
        if entry.is_dir():
            try:
                dir_name = entry.name
                # LATER: Make ports fixture return NamedPorts directly
                named_ports = isctest.instance.NamedPorts(
                    dns=int(ports["PORT"]), rndc=int(ports["CONTROLPORT"])
                )
                instance = isctest.instance.NamedInstance(dir_name, named_ports)
                instances[dir_name] = instance
            except ValueError:
                continue
    return instances


@pytest.fixture(scope="module")
def ns1(servers):
    return servers["ns1"]


@pytest.fixture(scope="module")
def ns2(servers):
    return servers["ns2"]


@pytest.fixture(scope="module")
def ns3(servers):
    return servers["ns3"]


@pytest.fixture(scope="module")
def ns4(servers):
    return servers["ns4"]


@pytest.fixture(scope="module")
def ns5(servers):
    return servers["ns5"]


@pytest.fixture(scope="module")
def ns6(servers):
    return servers["ns6"]


@pytest.fixture(scope="module")
def ns7(servers):
    return servers["ns7"]


@pytest.fixture(scope="module")
def ns8(servers):
    return servers["ns8"]


@pytest.fixture(scope="module")
def ns9(servers):
    return servers["ns9"]


@pytest.fixture(scope="module")
def ns10(servers):
    return servers["ns10"]


@pytest.fixture(scope="module")
def ns11(servers):
    return servers["ns11"]
