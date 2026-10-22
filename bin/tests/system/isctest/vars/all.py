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

from collections.abc import Iterator, Mapping
from typing import Any

from .algorithms import ALG_VARS, CRYPTO_SUPPORTED_VARS
from .autoconf import AC_VARS  # type: ignore
from .basic import BASIC_VARS
from .dirs import DIR_VARS
from .features import FEATURE_VARS
from .openssl import OPENSSL_VARS
from .ports import PORT_VARS


class VarLookup(Mapping[str, Any]):
    """
    A read-only mapping to coalesce the variables from different modules
    without making a copy (which would prevent updating these values from
    inside the modules). Values which are None are treated as unset when
    iterating.
    """

    def __init__(self, *maps: Mapping[str, str | None]):
        keys: set[str] = set()
        for m in maps:
            overlap = keys.intersection(m.keys())
            if overlap:
                raise RuntimeError(f"key(s) are defined multiple times: {overlap}")
            keys = keys.union(m.keys())
        self._maps = maps

    def __getitem__(self, key: str) -> Any:
        for m in self._maps:
            if key in m:
                return m[key]
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        for m in self._maps:
            for key, val in m.items():
                if val is not None:
                    yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)


ALL = VarLookup(
    AC_VARS,
    BASIC_VARS,
    FEATURE_VARS,
    OPENSSL_VARS,
    PORT_VARS,
    DIR_VARS,
    ALG_VARS,
    CRYPTO_SUPPORTED_VARS,
)
