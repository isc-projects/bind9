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

import os
import sys
import time

import gitlab


def init_gitlab_project():
    if os.getenv("CI_SERVER_URL", None) is not None:
        url = os.getenv("CI_SERVER_URL")
        job_token = os.environ["CI_JOB_TOKEN"]
        gl = gitlab.Gitlab(url, job_token=job_token)
    else:  # running locally on dev machine
        gl = gitlab.Gitlab.from_config()
    return gl.projects.get("isc-projects/bind9-shotgun-ci")


def parse_parent_pipeline_id():
    if len(sys.argv) != 2:
        raise RuntimeError("usage: util/ci-wait-shotgun.py PIPELINE_ID")
    try:
        return int(sys.argv[1])
    except ValueError as exc:
        raise RuntimeError("error: PIPELINE_ID must be a number") from exc


def wait_until(callback, timeout=1800, retry=10):
    start = time.time()
    while time.time() - start < timeout:
        if callback():
            return
        time.sleep(retry)
    raise RuntimeError(f"error: timed out after {timeout}s")


def get_child_pipeline_id(project, pipeline_id):
    pipeline = project.pipelines.get(pipeline_id)

    def pipeline_finished():
        pipeline.refresh()
        return pipeline.finished_at is not None

    wait_until(pipeline_finished, timeout=3000)

    bridges = pipeline.bridges.list()
    if len(bridges) != 1:
        raise RuntimeError("error: expected exactly one child pipeline")
    return bridges[0].downstream_pipeline["id"]


def get_postproc_job(project, pipeline_id):
    pipeline = project.pipelines.get(pipeline_id)
    postproc_job = None

    def job_finished():
        nonlocal postproc_job
        for job in pipeline.jobs.list(get_all=True):
            if job.name == "postproc":
                postproc_job = job
        if postproc_job is None:
            raise RuntimeError("error: failed to find 'postproc' job in child pipeline")
        return postproc_job.finished_at is not None

    wait_until(job_finished)
    return postproc_job


def evaluate_postproc_job(job):
    if job.status != "success":
        raise RuntimeError("error: 'postproc' job didn't succeed")
    index_url = (
        "https://isc-projects.gitlab-pages.isc.org/-/"
        f"bind9-shotgun-ci/-/jobs/{job.id}/artifacts/index.html"
    )
    print(f"Result ready for manual inspection: {index_url}")


def main():
    project = init_gitlab_project()
    parent_pipeline_id = parse_parent_pipeline_id()
    child_pipeline_id = get_child_pipeline_id(project, parent_pipeline_id)
    postproc_job = get_postproc_job(project, child_pipeline_id)
    evaluate_postproc_job(postproc_job)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as err:
        print(err)
        sys.exit(1)
