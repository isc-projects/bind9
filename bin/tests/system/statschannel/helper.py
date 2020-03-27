############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

from datetime import datetime, timedelta

# ISO datetime format without msec
fmt = '%Y-%m-%dT%H:%M:%SZ'

# The constants were taken from BIND 9 source code (lib/dns/zone.c)
max_refresh = timedelta(seconds=2419200)  # 4 weeks
max_expires = timedelta(seconds=14515200)  # 24 weeks
now = datetime.utcnow().replace(microsecond=0)
dayzero = datetime.utcfromtimestamp(0).replace(microsecond=0)


# Generic helper functions
def check_expires(expires, min, max):
    assert expires >= min
    assert expires <= max


def check_refresh(refresh, min, max):
    assert refresh >= min
    assert refresh <= max


def check_loaded(loaded, expected):
    # Sanity check the zone timers values
    assert loaded == expected
    assert loaded < now


def check_zone_timers(loaded, expires, refresh, loaded_exp):
    # Sanity checks the zone timers values
    if expires is not None:
        check_expires(expires, now, now + max_expires)
    if refresh is not None:
        check_refresh(refresh, now, now + max_refresh)
    check_loaded(loaded, loaded_exp)


def zone_mtime(zonedir, name):
    import os
    import os.path
    from datetime import datetime

    si = os.stat(os.path.join(zonedir, "{}.db".format(name)))
    mtime = datetime.utcfromtimestamp(si.st_mtime).replace(microsecond=0)

    return mtime
