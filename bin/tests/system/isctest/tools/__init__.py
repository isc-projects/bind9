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

"""
Standalone helper tools for system tests.

Unlike the rest of the isctest package, which is imported by the pytest
runner and test modules, every module in isctest.tools is also runnable
as a standalone script:

    $PYTHON -m isctest.tools.<name> [args]

This is how legacy tests.sh scripts invoke them (conf.sh puts the
isctest package on PYTHONPATH).  Once a test is ported to pytest, the
same module is imported and its functions called directly.  Keep each
tool self-contained: no dependencies on the rest of isctest.
"""
