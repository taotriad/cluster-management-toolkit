# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Match the end of a block used by the block parser.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.logparser.logparser_types import MatchBlockEnd


# pylint: disable-next=too-many-branches
def match_block_end(matchrules: list[MatchBlockEnd], message: str) -> tuple[bool, bool]:
    """
    Find a block end; returns False if the block end is found.

        Parameters:
            matchrules ([MatchBlockEnd]): A list of matchrules
            message (str): The message to match against the matchrules
        Returns:
            (bool, bool, bool):
                (bool): Was there a match?
                (bool): Should the block end be formatted?
    """
    matched: bool = True
    format_block_end: bool = False

    for _be in matchrules:
        matchtype = deep_get(_be, DictPath("matchtype"))
        matchkey = deep_get(_be, DictPath("matchkey"))
        format_block_end = deep_get(_be, DictPath("format_block_end"), False)

        # We can only match None against EOF.
        if message is None:
            if matchtype == "eof":
                matched = False
                break
            continue
        if matchtype == "empty":
            if not message.strip():
                matched = False
        elif matchtype == "contains":
            if matchkey in message:
                matched = False
        elif matchtype == "exact":
            if message == matchkey:
                matched = False
        elif matchtype == "endswith":
            if message.endswith(matchkey):
                matched = False
        elif matchtype == "search":
            tmp = matchkey.search(message)
            if tmp is not None:
                matched = False
        elif matchtype in ("regex", "match"):
            tmp = matchkey.match(message)
            if tmp is not None:
                matched = False
        elif matchtype == "startswith" and message.startswith(matchkey):
            matched = False

    return matched, format_block_end
