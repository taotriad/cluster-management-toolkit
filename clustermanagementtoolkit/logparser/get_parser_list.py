# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.logparser import logparser_types


def get_parser_list() -> set[str]:
    """
    Return a set with the parsers that should be visible in the override menu.

        Returns:
            (set(Parser)): A set of parsers
    """
    parsers_ = set()
    for parser in logparser_types.parsers:
        if not parser.show_in_selector:
            continue
        parsers_.add(parser.name)

    return parsers_
