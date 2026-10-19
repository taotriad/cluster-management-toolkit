# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmtlib import none_timestamp

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.logparser.match_block_end import match_block_end
from clustermanagementtoolkit.logparser.split_iso_timestamp import split_iso_timestamp


def strip_timestamp_and_match_block_end(message: str, **kwargs: Any) -> tuple[str, bool, bool]:
    """
    Blocks are likely to be preceded by a timestamp, so we need to strip if before we can
    pass it to match_block_end().

        Parameters:
            message (str): The string to match
            **kwargs (dict[str, Any]): Keyword arguments
                block_end ([MatchBlockEnd]): The block end rules
                strip_tab (bool): Some blocks are tab-indented, which may confuse some formatters;
                                  this option allows for stripping the first leading tab.
        Returns:
            (str, bool):
                (str): The processed string
                (bool): True if this is the end, False if not
                (bool): True if the block end should be formatted
    """
    block_end = deep_get(kwargs, DictPath("block_end"), [])
    strip_tab = deep_get(kwargs, DictPath("strip_tab"), False)

    if message is not None:
        _timestamp, message = split_iso_timestamp(message, none_timestamp())
        if strip_tab and message.startswith("\t"):
            message = message[1:]

    matched, format_block_end = match_block_end(block_end, message)
    return message, not matched, format_block_end
