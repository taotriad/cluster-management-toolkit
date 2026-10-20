# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Match the start of a block used by the block parser.
"""

import re
from typing import cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.logparser.logparser_types import MatchBlockStart


# pylint: disable-next=too-many-branches
def match_block_start(matchrules: list[MatchBlockStart],
                      message: str, line: int) -> tuple[list[str], bool]:
    """
    Find a block start; returns False if the block end is found additional rules.

        Parameters:
            matchrules ([MatchBlockStart]): A list of matchrules
            message (str): The message to match against the matchrules
            line (int): The line number
        Returns:
            ([str], bool):
                ([str]): The list of matches if matched, empty list if no match
                (bool): Should the block start be formatted?
    """
    matched: list[str] = []
    format_block_start: bool = False

    for _bs in matchrules:
        matchtype = deep_get(_bs, DictPath("matchtype"))
        matchkey = deep_get(_bs, DictPath("matchkey"))
        matchline = deep_get(_bs, DictPath("matchline"), "any")
        format_block_start = deep_get(_bs, DictPath("format_block_start"), False)
        if matchline == "any" or matchline == "first" and not line:
            if matchtype == "contains":
                if cast(str, matchkey) in message:
                    matched = [message]
            elif matchtype == "exact":
                if message == cast(str, matchkey):
                    matched = [message]
            elif matchtype == "endswith":
                if message.endswith(cast(str, matchkey)):
                    matched = [message]
            elif matchtype == "search":
                tmp = cast(re.Pattern[str], matchkey).search(message)
                if tmp is not None:
                    # If the regex matches groups, it means we want the message split into
                    # multiple lines; this is useful, for instance, when we have something
                    # like this:
                    # New Configuration: {
                    # <json goes here>
                    # }
                    if tmp.groups():
                        matched = list(tmp.groups())
                    else:
                        matched = [message]
            elif matchtype in ("regex", "match"):
                tmp = cast(re.Pattern[str], matchkey).match(message)
                if tmp is not None:
                    # If the regex matches groups, it means we want the message split into
                    # multiple lines; this is useful, for instance, when we have something
                    # like this:
                    # New Configuration: {
                    # <json goes here>
                    # }
                    if tmp.groups():
                        matched = list(tmp.groups())
                    else:
                        matched = [message]
            elif matchtype == "startswith" and message.startswith(cast(str, matchkey)):
                matched = [message]
        if matched:
            break
    return matched, format_block_start
