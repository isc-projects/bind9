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

import yaml

NUMBER_OF_TESTS_PER_TSAN_JOB = 50

with open(".gitlab-ci.yml", encoding="utf-8") as gitlab_ci_yml:
    anchors = yaml.load(gitlab_ci_yml, Loader=yaml.Loader)

for tsan_job in "gcc:tsan", "clang:tsan":
    tsan_stress_test_job = anchors[f"system:{tsan_job}"]
    tsan_stress_test_job["stage"] = "test"
    tsan_stress_test_job["rules"] = [{"if": '$CI_PIPELINE_SOURCE == "parent_pipeline"'}]
    tsan_stress_test_job["parallel"] = NUMBER_OF_TESTS_PER_TSAN_JOB
    tsan_stress_test_job["needs"] = [
        {"pipeline": "$PARENT_PIPELINE_ID", "job": tsan_job}
    ]
    del tsan_stress_test_job["only"]

    print(
        yaml.dump(
            {f"system:{tsan_job}:stress": tsan_stress_test_job},
            Dumper=yaml.Dumper,
        )
    )
