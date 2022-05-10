############################################################################
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
############################################################################

"""
Sphinx domains for ISC configuration files.

Use setup() to install new Sphinx domains for ISC configuration files.

This extension is based on combination of two Sphinx extension tutorials:
https://www.sphinx-doc.org/en/master/development/tutorials/todo.html
https://www.sphinx-doc.org/en/master/development/tutorials/recipe.html
"""

from sphinx import addnodes
from sphinx.directives import ObjectDescription
from sphinx.domains import Domain
from sphinx.roles import XRefRole
from sphinx.util.nodes import make_refnode


# pylint: disable=too-many-statements
def domain_factory(domainname, domainlabel):
    """
    Return parametrized Sphinx domain object.
    @param domainname Name used when referencing domain in .rst: e.g. namedconf
    @param confname Humand-readable name for texts, e.g. named.conf
    """

    class ISCConfDomain(Domain):
        """
        Custom Sphinx domain for ISC config.
        Provides .. statement:: directive to define config statement.
        :ref:`statementname` works as usual.

        See https://www.sphinx-doc.org/en/master/extdev/domainapi.html
        """

        class StatementDirective(ObjectDescription):
            """
            A custom directive that describes a statement,
            e.g. max-cache-size.
            """

            has_content = True
            required_arguments = 1
            option_spec = {}

            def handle_signature(self, sig, signode):
                signode += addnodes.desc_name(text=sig)
                return sig

            def add_target_and_index(self, _name_cls, sig, signode):
                signode["ids"].append(domainname + "-statement-" + sig)

                iscconf = self.env.get_domain(domainname)
                iscconf.add_statement(sig)

        name = domainname
        label = domainlabel

        directives = {
            "statement": StatementDirective,
        }

        roles = {"ref": XRefRole(warn_dangling=True)}
        initial_data = {
            "statements": [],  # object list for Sphinx API
        }

        indices = {}  # no custom indicies

        def get_objects(self):
            """Sphinx API: iterable of object descriptions"""
            for obj in self.data["statements"]:
                yield obj

        # pylint: disable=too-many-arguments
        def resolve_xref(self, env, fromdocname, builder, typ, target, node, contnode):
            """
            Sphinx API:
            Resolve the pending_xref *node* with the given typ and target.
            """
            match = [
                (docname, anchor)
                for name, sig, typ, docname, anchor, _prio in self.get_objects()
                if sig == target
            ]

            if len(match) == 0:
                return None
            todocname = match[0][0]
            targ = match[0][1]

            refnode = make_refnode(
                builder, fromdocname, todocname, targ, contnode, targ
            )
            return refnode

        def resolve_any_xref(self, env, fromdocname, builder, target, node, contnode):
            """
            Sphinx API:
            Raising NotImplementedError uses fall-back bassed on resolve_xref.
            """
            raise NotImplementedError

        def add_statement(self, signature):
            """
            Add a new statement to the domain data structures.
            No visible effect.
            """
            name = "{}.{}.{}".format(domainname, "statement", signature)
            anchor = "{}-statement-{}".format(domainname, signature)

            # Sphinx API: name, dispname, type, docname, anchor, priority
            self.data["statements"].append(
                (
                    name,
                    signature,
                    domainlabel + " statement",
                    self.env.docname,
                    anchor,
                    1,
                )
            )

        def clear_doc(self, docname):
            """
            Sphinx API: like env-purge-doc event, but in a domain.

            Remove traces of a document in the domain-specific inventories.
            """
            self.data["statements"] = list(
                obj for obj in self.data["statements"] if obj[3] != docname
            )

        def merge_domaindata(self, docnames, otherdata):
            """Sphinx API: Merge in data regarding *docnames* from a different
            domaindata inventory (coming from a subprocess in parallel builds).

            @param otherdata is self.data equivalent from another process

            Beware: As of Sphinx 4.5.0, this is called multiple times in a row
            with the same data and has to guard against duplicites.  It seems
            that all existing domains in Sphinx distribution have todo like
            "deal with duplicates" but do nothing about them, so we just follow
            the suite."""
            self.data["statements"] = list(
                set(self.data["statements"] + otherdata["statements"])
            )

    return ISCConfDomain


def setup(app, domainname, confname):
    """
    Install new parametrized Sphinx domain.
    """

    Conf = domain_factory(domainname, confname)
    app.add_domain(Conf)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
