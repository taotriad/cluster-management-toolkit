# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

# The parser takes one line of input at a time;
# for messages that need multi-line parsing you need to
# return remnants and if necessary tweak multiline_parser
#
# Log levels are the same as in syslog:
# EMERG        system is unusable <should be irrelevant>
# ALERT        action must be taken immediately
# CRIT         critical conditions
# ERR          error conditions
# WARNING      warning conditions
# NOTICE       normal, but significant, condition
# INFO         informational message
# DEBUG        debug-level message
#
# Return format is timestamp, facility, severity, message

"""
Log parsers for cmu.

unit-tests:
    tests/logtests
"""

# pylint: disable=line-too-long
from clustermanagementtoolkit.logparser.custom_override_severity import custom_override_severity
from clustermanagementtoolkit.logparser.custom_splitter import custom_splitter
from clustermanagementtoolkit.logparser.directory import directory
from clustermanagementtoolkit.logparser.get_parser_list import get_parser_list
from clustermanagementtoolkit.logparser.http import http
from clustermanagementtoolkit.logparser.initialise_logparser import initialise_logparser
from clustermanagementtoolkit.logparser.init_logparser_configuration import init_logparser_configuration  # noqa: E501
from clustermanagementtoolkit.logparser.init_parser_list import init_parser_list
from clustermanagementtoolkit.logparser.iptables import iptables
from clustermanagementtoolkit.logparser.is_timestamp import is_timestamp
from clustermanagementtoolkit.logparser.key_value import key_value
from clustermanagementtoolkit.logparser.letter_to_severity import letter_to_severity
from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration
from clustermanagementtoolkit.logparser.logparser import logparser
from clustermanagementtoolkit.logparser.lvl_to_4letter_severity import lvl_to_4letter_severity
from clustermanagementtoolkit.logparser.lvl_to_letter_severity import lvl_to_letter_severity
from clustermanagementtoolkit.logparser.lvl_to_word_severity import lvl_to_word_severity
from clustermanagementtoolkit.logparser.month_to_numerical import month_to_numerical
from clustermanagementtoolkit.logparser.modinfo import modinfo
from clustermanagementtoolkit.logparser.seconds_severity_facility import seconds_severity_facility
from clustermanagementtoolkit.logparser.severity_to_string import severity_to_string
from clustermanagementtoolkit.logparser.split_bracketed_severity import split_bracketed_severity
from clustermanagementtoolkit.logparser.split_glog import split_glog
from clustermanagementtoolkit.logparser.split_iso_timestamp import split_iso_timestamp
from clustermanagementtoolkit.logparser.split_json_style import split_json_style
from clustermanagementtoolkit.logparser.str_3letter_to_severity import str_3letter_to_severity
from clustermanagementtoolkit.logparser.str_4letter_to_severity import str_4letter_to_severity
from clustermanagementtoolkit.logparser.str_to_severity import str_to_severity
from clustermanagementtoolkit.logparser.strip_iso_timestamp import strip_iso_timestamp
from clustermanagementtoolkit.logparser.strip_iso_timestamp_with_tz import strip_iso_timestamp_with_tz  # noqa: E501
from clustermanagementtoolkit.logparser.sysctl import sysctl
from clustermanagementtoolkit.logparser.tab_separated import tab_separated
# pylint: enable=line-too-long

__all__ = [
    "LogparserConfiguration",
    "custom_override_severity",
    "custom_splitter",
    "directory",
    "get_parser_list",
    "http",
    "init_logparser_configuration",
    "init_parser_list",
    "initialise_logparser",
    "iptables",
    "is_timestamp",
    "key_value",
    "letter_to_severity",
    "logparser",
    "lvl_to_4letter_severity",
    "lvl_to_letter_severity",
    "lvl_to_word_severity",
    "modinfo",
    "month_to_numerical",
    "seconds_severity_facility",
    "severity_to_string",
    "split_bracketed_severity",
    "split_glog",
    "split_iso_timestamp",
    "split_json_style",
    "str_3letter_to_severity",
    "str_4letter_to_severity",
    "str_to_severity",
    "strip_iso_timestamp",
    "strip_iso_timestamp_with_tz",
    "sysctl",
    "tab_separated",
]
