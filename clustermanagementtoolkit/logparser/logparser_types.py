# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Various types used by the logparser.
"""

from collections.abc import Callable
import re
from typing import Any, ClassVar, Literal, NamedTuple, TypedDict

from clustermanagementtoolkit.cmttypes import LogLevel


class MatchBlockStart(TypedDict):
    """
    A match-rule for block parsers; this one for finding block starts.
    """
    matchtype: Literal[
        "contains",
        "endswith",
        "match",
        "regex",
        "search",
        "startswith"]
    matchkey: str | re.Pattern[str]
    matchline: Literal["any", "first"]
    format_block_start: bool


class MatchBlockEnd(TypedDict):
    """
    A match-rule for block parsers; this one for finding block ends.
    """
    matchtype: Literal[
        "contains",
        "empty",
        "endswith",
        "eof",
        "match",
        "regex",
        "search",
        "startswith"]
    matchkey: str | re.Pattern[str]
    matchline: Literal["any", "end"]
    format_block_end: bool


class LogBlock(TypedDict, total=False):
    """
    Block processing instructions.
    """
    scanner: Callable
    formatter: Callable | None
    options: dict
    severity: LogLevel
    unprocessed_lines: list[str]


# pylint: disable-next=too-few-public-methods
class LogparserConfiguration:
    """
    Various configuration options used by the logparsers
    """
    # Keep or strip timestamps in structured logs
    pop_ts: ClassVar[bool] = False
    # Keep or strip severity in structured logs
    pop_severity: ClassVar[bool] = False
    # Keep or strip facility in structured logs
    pop_facility: ClassVar[bool] = False
    # msg="foo" or msg=foo => foo
    msg_extract: ClassVar[bool] = False
    # If msg_extract is False,
    # this decides whether or not to put msg="foo" first or not
    # this also affects err="foo" and error="foo"
    msg_first: ClassVar[bool] = False
    # Should override severity rules be applied?
    override_severity: ClassVar[bool] = True
    # Are parser-files read from BUNDLE.yaml?
    using_bundles: ClassVar[bool] = False


class ParserRule(NamedTuple):
    """
    A single parser-rule directive.

        Parameters:
            rule_name (str): The rule to apply (see parsers/README.md)
            options (dict[str, Any]): The options to pass to the rule (see parsers/README.md)
    """
    rule_name: str
    options: dict[str, Any]


class MatchRule(NamedTuple):
    """
    A rule to use when identifying what containers the parser-rules apply to.
    One of pod_name, container_name, image_name, or image_regex is required.
    Stricter matcher is typically better, since it prevents the parser-rules from
    overriding unrelated logs.

        Parameters:
            pod_name (str): The ^prefix, suffix$ or ^exact match$ for the pod
            container_name (str): The ^prefix, suffix$ or ^exact match$ for the container
            image_name (str): The ^prefix, suffix$ or ^exact match$ for the image
            image_regex (re.Pattern[str]): A regular expression that matches the image name
            container_type ("Container", "InitContainer"): The container type; default "Container"
    """
    pod_name: str
    container_name: str
    image_name: str
    container_type: Literal["InitContainer", "Container"]
    image_regex: re.Pattern[str] | None


class Parser(NamedTuple):
    """
    A parser-file rule to be used when the log from a container.

        Parameters:
            name (str): The name of the parser-file rule; NOT unique; if you want multiple
                        rules to share the same name (for instance when you have a class
                        of different logs that all belong to the same project, but require
                        different parser-rules) you can; these will be identified by
                        their MatchRules instead.
            show_in_selector (bool): Show the rule in the Override Parser list; should typically
                                     only be specified for generic rules. Default: False.
            match ([MatchRule]): The rules used to identifying what containers the parser-rule
                                 applies to.
            rules ([ParserRule]): The parser-rules to apply to the container log.
    """
    name: str
    show_in_selector: bool
    match: list[MatchRule]
    rules: list[ParserRule]


logparser_configkeys: dict[str, dict[str, str | bool]] = {
    "pop_ts": {
        "key": "Pod#pop_timestamps",
        "default": False
    },
    "pop_severity": {
        "key": "Pod#pop_severity",
        "default": False,
    },
    "pop_facility": {
        "key": "Pod#pop_facility",
        "default": False,
    },
    "msg_extract": {
        "key": "Pod#extract_message",
        "default": False,
    },
    "msg_first": {
        "key": "Pod#message_first",
        "default": False,
    },
    "override_severity": {
        "key": "Pod#override_severity",
        "default": True,
    },
    "merge_starting_version": {
        "key": "Pod#merge_starting_version",
        "default": False,
    },
}


parsers: list[Parser] = []
