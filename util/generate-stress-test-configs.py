#!/usr/bin/env python3

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

import itertools
import os
import random

import yaml

with open(".gitlab-ci.yml", encoding="utf-8") as gitlab_ci_yml:
    anchors = yaml.load(gitlab_ci_yml, Loader=yaml.Loader)

# Mandatory environment variables
ci_pipeline_source = os.environ["CI_PIPELINE_SOURCE"]
install_path = os.environ["INSTALL_PATH"]
project_directory = os.environ["CI_PROJECT_DIR"]

# Optional environment variables
all_bind_stress_tests = os.getenv("ALL_BIND_STRESS_TESTS")
build_parallel_jobs = os.getenv("BUILD_PARALLEL_JOBS", "1")
cflags_common = os.getenv("CFLAGS_COMMON", "")
ci_commit_tag = os.getenv("CI_COMMIT_TAG")

# Optional overrides for default test parameters
env_traffic_rate = os.getenv("BIND_STRESS_TESTS_RATE")
env_run_time = os.getenv("BIND_STRESS_TESTS_RUN_TIME")

# Tags and scheduled pipelines produce longer jobs.
if ci_commit_tag or ci_pipeline_source == "schedule":
    all_bind_stress_tests = True
    scenario = "long"
    default_runtime = 60
    expire_in = "1 week"
else:
    scenario = "short"
    default_runtime = 15
    expire_in = "1 day"

ALL_MODES = "recursive", "authoritative", "rpz"
ALL_PROTOCOLS = "tcp", "doh", "dot"
ALL_PLATFORMS = ".fedora-41-amd64", ".fedora-41-arm64", ".freebsd-stress-amd64"

# If ALL_BIND_STRESS_TESTS and CI_COMMIT_TAG environmental variables are unset,
# pick only two of three items from "modes", "protocols", and "machines" to make
# the "modes x protocols x machines" matrix smaller.
if all_bind_stress_tests is None and ci_commit_tag is None:
    modes = random.sample(ALL_MODES, k=2)
    protocols = random.sample(ALL_PROTOCOLS, k=2)
    platforms = random.sample(ALL_PLATFORMS, k=2)
else:
    modes = ALL_MODES
    protocols = ALL_PROTOCOLS
    platforms = ALL_PLATFORMS

jobs = {}

for mode, protocol, platform in itertools.product(modes, protocols, platforms):
    if "freebsd" in platform:
        # Flamethrower-produced DoH queries on FreeBSD always timeout. Skip
        # DoH-on-FreeBSD jobs.
        if protocol == "doh":
            continue
        job_platform = "freebsd:amd64"
        compiler_binary = "clang"
        flame_binary = "/usr/local/bin/flame"
    else:
        if "amd64" in platform:
            job_platform = "linux:amd64"
        else:
            job_platform = "linux:arm64"
        compiler_binary = "gcc"
        flame_binary = "/usr/bin/flame"

    if mode == "rpz":
        default_traffic_rate = 1500
    else:
        default_traffic_rate = 10000

    traffic_rate = int(env_traffic_rate or default_traffic_rate)
    runtime = int(env_run_time or default_runtime)

    expected_tcp_response_rate = 80 if protocol == "dot" else 90

    job_definition = {
        "stage": "test",
        "variables": {
            "CC": compiler_binary,
            "CFLAGS": f"{cflags_common} -Og",
            "EXPECTED_TCP_RESPONSE_RATE": expected_tcp_response_rate,
            "FLAME": flame_binary,
            "MODE": mode,
            "PROTOCOL": f"{protocol} udp",
            "RATE": traffic_rate,
            "RUN_TIME": runtime,
        },
        "script": [
            "autoreconf -fi",
            *anchors[".configure"],
            *anchors[".setup_interfaces"],
            f"make -j{build_parallel_jobs} -k all V=1",
            f'make DESTDIR="{install_path}" install',
            "git clone --depth 1 https://gitlab.isc.org/isc-projects/bind9-qa.git",
            "cd bind9-qa/stress",
            f'export LD_LIBRARY_PATH="{install_path}/usr/local/lib"',
            f'export BIND_INSTALL_PATH="{install_path}/usr/local"',
            f'export WORKSPACE="{project_directory}"',
            "bash stress.sh",
        ],
        "rules": [{"if": '$CI_PIPELINE_SOURCE == "parent_pipeline"'}],
        "timeout": f"{runtime + 30} minutes",
        "artifacts": {
            "untracked": True,
            "when": "always",
            "expire_in": expire_in,
            "exclude": [
                "output/ns4/*.dtq*",
                "output/ns4/large-delta-rpz*.local",
                "output/rpz_*",
            ],
        },
    }

    job_definition |= anchors[platform]

    job_name = f"stress:{scenario}:{mode}:{protocol}+udp:{job_platform}"
    jobs[job_name] = job_definition


print(yaml.dump(jobs, Dumper=yaml.Dumper))
