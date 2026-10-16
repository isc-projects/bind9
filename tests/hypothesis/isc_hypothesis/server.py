# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import contextlib
import os
import select
import struct
import subprocess

TIMEOUT = 10
MAX_RESPONSE_SIZE = 4 * 1024 * 1024
LENGTH_PREFIX = struct.Struct("!I")


class _ProtobufServer:
    """
    Drive a helper binary that reads length-prefixed protobuf requests on
    stdin and writes length-prefixed protobuf responses on stdout.

    The process starts on construction and must be torn down with
    shutdown() or close().
    """

    def __init__(self, path, response_type):
        self._path = path
        self._response_type = response_type
        # pylint: disable=consider-using-with
        self._proc = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    @property
    def running(self):
        return self._proc.poll() is None

    def command(self, request):
        """
        Send one request and return the decoded response.
        """
        if not self.running:
            self._fail("exited")

        data = request.SerializeToString()
        try:
            self._proc.stdin.write(LENGTH_PREFIX.pack(len(data)) + data)
            self._proc.stdin.flush()
        except BrokenPipeError:
            self._fail("broken pipe")

        (length,) = LENGTH_PREFIX.unpack(self._read(LENGTH_PREFIX.size))
        if length > MAX_RESPONSE_SIZE:
            self._fail(f"response too large ({length} bytes)")
        return self._response_type.FromString(self._read(length))

    def shutdown(self):
        """
        Ask the server to exit and check that it did so cleanly.
        """
        try:
            self._proc.stdin.close()
            code = self._proc.wait(timeout=TIMEOUT)
            if code != 0:
                self._fail(f"exit status {code}")
        finally:
            self.close()

    def close(self):
        """
        Tear down the process without checking its exit status.
        """
        if self.running:
            self._proc.kill()
            self._proc.wait()
        # A failed write leaves the request buffered; closing flushes it.
        with contextlib.suppress(BrokenPipeError):
            self._proc.stdin.close()
        self._proc.stdout.close()

    def _fail(self, reason):
        # Reap (or kill) the process, so that it is no longer running.
        try:
            self._proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        raise AssertionError(f"{self._path}: {reason}")

    def _read(self, size):
        # Bypass the buffered reader so that select() sees all pending data.
        fd = self._proc.stdout.fileno()
        data = bytearray()
        while len(data) < size:
            ready, _, _ = select.select([fd], [], [], TIMEOUT)
            if not ready:
                self._proc.kill()
                self._fail("timed out")
            chunk = os.read(fd, size - len(data))
            if not chunk:
                self._fail("EOF")
            data.extend(chunk)
        return bytes(data)


class RestartingProtobufServer:
    """
    A _ProtobufServer that is replaced with a fresh one whenever it dies, so
    that a single crash fails only the example that caused it.
    """

    def __init__(self, path, response_type):
        self._args = (path, response_type)
        self._server = None

    def __enter__(self):
        self._server = _ProtobufServer(*self._args)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        _ = exc_value, traceback  # Silence vulture spurious warnings
        if exc_type is None:
            self._server.shutdown()
        else:
            self._server.close()

    def command(self, request):
        """
        Send one request, restarting the server first if it died.
        """
        if not self._server.running:
            # Already reaped; dropping it closes its pipes.
            self._server = _ProtobufServer(*self._args)
        return self._server.command(request)
