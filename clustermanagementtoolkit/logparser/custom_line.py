# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A block scanner.
"""

from collections.abc import Callable
from typing import Any, cast

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name
from clustermanagementtoolkit.cmttypes import name_to_loglevel

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit import formatters

from clustermanagementtoolkit.logparser.custom_override_severity import custom_override_severity
from clustermanagementtoolkit.logparser.logparser_types import LogBlock
from clustermanagementtoolkit.logparser.logparser_types import MatchBlockStart
from clustermanagementtoolkit.logparser.match_block_start import match_block_start
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.logparser.strip_timestamp_and_match_block_end import strip_timestamp_and_match_block_end  # noqa: E501


# pylint: disable-next=too-many-locals
def custom_line(message: str, **kwargs: Any) -> tuple[LogLevel, list[ThemeRef | ThemeStr] | str,
                                                      LogBlock]:
    """
    Parser for custom block messages.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments
                options (dict[str, Any]):
                    loglevel (str): The default loglevel to use for processed entries
                    eof (str): Should EOF be regarded as a block end?
                    block_start ([dict[str, str | bool]]):
                        matchtype (str): The type of match; must be one of:
                                         - "contains"
                                         - "endswith"
                                         - "exact"
                                         - "match"
                                         - "regex"
                                         - "search"
                                         - "startswith"
                        matchkey (str): The key (either a plain string or a regular expression)
                                        to use when matching
                        matchline (str): Where can a match occur? "any" matches any line,
                                         "first" only matches the first line in a log message
                        format_block_start (bool): Should the first line of the block be formatted?
                    block_end ([dict[str, str | bool]]): [unused]
                    overrides ([dict[str, str]]): A list of severity override match rules
                                                  to pass to custom_override_severity()
                        matchtype (str): The type of match; must be one of:
                                         - "contains"
                                         - "endswith"
                                         - "exact"
                                         - "regex"
                                         - "startswith"
                        matchkey (str): The key (either a plain string or a regular expression)
                                        to use when matching
                        loglevel (str): The loglevel to return if the condition matches
        Returns:
            (ThemeArray | str, LogLevel, dict[str, Any]):
                (LogLevel): The severity; this will be used by the matched line,
                            but also, unless the scanner extracts something else, for the block
                (ThemeArray): The matched line, if not being processed by the scanner
                (LogBlock): Block processor instructions
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.DEFAULT)
    options: dict = deep_get(kwargs, DictPath("options"), {})

    strip_ansicodes: bool = deep_get(options, DictPath("strip_ansicodes"), False)
    block_start: list[MatchBlockStart] = deep_get(options, DictPath("block_start"), [])
    # This is the loglevel to apply to the block if it matches.
    loglevel_name: str = deep_get(options, DictPath("severity#default"), "info")

    base_severity: LogLevel = name_to_loglevel(loglevel_name, severity)

    processor: LogBlock = {}

    line = deep_get(options, DictPath("__line"), 0)

    matched, format_block_start = match_block_start(block_start, message, line)
    if matched:
        message = matched[0]
        unprocessed_lines = matched[1:]

    if strip_ansicodes:
        message = cmtlib.strip_ansicodes(message)
    new_severity, message = cast(tuple[LogLevel, str],
                                 custom_override_severity(message, base_severity, options=options))
    severity_name = f"severity_{loglevel_to_name(new_severity).lower()}"
    formatter: Callable | None = cmtlib.check_allowlist(formatters.formatter_allowlist,
                                                        "formatter_allowlist",
                                                        deep_get(options, DictPath("formatter")),
                                                        formatters.format_generic,
                                                        exit_on_fail=False)

    if matched:
        # If format_block_start is set we pass the block start along with the rest of the lines
        # to be parsed by the scanner (if possible).
        if format_block_start:
            new_message: list[ThemeRef | ThemeStr] = []
            unprocessed_lines = matched
        else:
            new_message = \
                [ThemeStr(message, ThemeAttr("logview", severity_name))]
        processor = {
            "scanner": strip_timestamp_and_match_block_end,
            "formatter": formatter,
            "options": options,
            "severity": new_severity,
            "unprocessed_lines": unprocessed_lines,
        }
        return severity, new_message, processor

    return severity, message, {}
