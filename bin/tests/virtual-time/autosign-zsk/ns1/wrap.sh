# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# $Id: wrap.sh,v 1.3 2010/06/21 23:46:48 tbox Exp $

#
# Wrapper for named
#

LD_PRELOAD=../../libvtwrapper.so
export LD_PRELOAD

exec $*
