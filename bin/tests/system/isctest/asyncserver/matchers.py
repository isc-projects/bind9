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

from collections.abc import Iterator
from typing import TypeVar

import abc

import dns.name
import dns.rdatatype

from .context import QueryContext

M = TypeVar("M", bound="Matcher")


class Matcher(abc.ABC):
    """
    A predicate over queries, deciding which ones a response handler handles.

    Matchers are combined with `&`, `|` and `~`; a handler declares the result
    in its `matcher` attribute.
    """

    @abc.abstractmethod
    def match(self, qctx: QueryContext) -> bool:
        """
        Whether the query in `qctx` matches.
        """
        raise NotImplementedError

    def __and__(self, other: "Matcher") -> "Matcher":
        return AllOf(self, other)

    def __or__(self, other: "Matcher") -> "Matcher":
        return AnyOf(self, other)

    def __invert__(self) -> "Matcher":
        return Not(self)

    def of(self, cls: type[M]) -> M:
        """
        The one matcher of class `cls` this matcher is built from, for a
        handler to read what it was declared with: `matcher.of(Qname).qnames`.
        """
        found = [m for m in self.leaves() if isinstance(m, cls)]
        assert len(found) == 1, f"{self} has {len(found)} {cls.__name__} matchers"
        return found[0]

    def leaves(self) -> Iterator["Matcher"]:
        """
        The matchers this one is built from; a matcher built from nothing
        yields itself.
        """
        yield self

    def __str__(self) -> str:
        return f"{self.__class__.__name__}()"


class _Combinator(Matcher):
    """
    Base class for matchers combining other matchers.
    """

    _SEPARATOR = ", "

    def __init__(self, *matchers: Matcher) -> None:
        self._matchers = matchers

    def leaves(self) -> Iterator[Matcher]:
        for matcher in self._matchers:
            yield from matcher.leaves()

    def __str__(self) -> str:
        return f"({self._SEPARATOR.join(str(m) for m in self._matchers)})"


class AllOf(_Combinator):
    """
    Match queries matched by every one of the given matchers (`a & b`).
    """

    _SEPARATOR = " and "

    def __and__(self, other: Matcher) -> Matcher:
        return AllOf(*self._matchers, other)

    def match(self, qctx: QueryContext) -> bool:
        return all(matcher.match(qctx) for matcher in self._matchers)


class AnyOf(_Combinator):
    """
    Match queries matched by at least one of the given matchers (`a | b`).
    """

    _SEPARATOR = " or "

    def __or__(self, other: Matcher) -> Matcher:
        return AnyOf(*self._matchers, other)

    def match(self, qctx: QueryContext) -> bool:
        return any(matcher.match(qctx) for matcher in self._matchers)


class Not(Matcher):
    """
    Match queries which the given matcher does not match (`~a`).
    """

    def __init__(self, matcher: Matcher) -> None:
        self._matcher = matcher

    def leaves(self) -> Iterator[Matcher]:
        yield from self._matcher.leaves()

    def match(self, qctx: QueryContext) -> bool:
        return not self._matcher.match(qctx)

    def __str__(self) -> str:
        return f"not {self._matcher}"


class Always(Matcher):
    """
    Match every query; the default for handlers which do not set a matcher.
    """

    def match(self, qctx: QueryContext) -> bool:
        return True


class Qname(Matcher):
    """
    Match queries whose QNAME is one of the given names.
    """

    def __init__(self, *qnames: str | dns.name.Name) -> None:
        self.qnames = [
            name if isinstance(name, dns.name.Name) else dns.name.from_text(name)
            for name in qnames
        ]

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qname in self.qnames

    def __str__(self) -> str:
        return f"QNAME in [{', '.join(str(name) for name in self.qnames)}]"


class Qtype(Matcher):
    """
    Match queries whose QTYPE is one of the given types.
    """

    def __init__(self, *qtypes: dns.rdatatype.RdataType) -> None:
        self.qtypes = qtypes

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype in self.qtypes

    def __str__(self) -> str:
        return f"QTYPE in [{', '.join(map(dns.rdatatype.to_text, self.qtypes))}]"
