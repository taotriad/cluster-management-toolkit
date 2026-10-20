# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert LogLevel to a string representation, to be used when exporting logs to file.
"""

from clustermanagementtoolkit.cmttypes import LogLevel

from clustermanagementtoolkit.logparser.lvl_to_4letter_severity import lvl_to_4letter_severity
from clustermanagementtoolkit.logparser.lvl_to_letter_severity import lvl_to_letter_severity
from clustermanagementtoolkit.logparser.lvl_to_word_severity import lvl_to_word_severity


def severity_to_string(lvl: LogLevel, severity_format: str = "full",
                       default: str = "") -> str:
    """
    Convert a LogLevel to a string representation.

        Parameters:
            lvl (LogLevel): A LogLevel
            severity_format (str): The desired format; one of:
                                   letter|Letter|LETTER
                                   4letter|4Letter|4LETTER
                                   full|Full|FULL
                                   If the string is in lowercase the output will be in lowercase.
                                   If the string is capitalized the output will be capitalized.
                                   If the string is all caps the output will be all caps.
            default (str): Default value to return if the severity_format is invalid,
                           or the LogLevel lacks representation.
        Returns:
            (str): The corresponding severity string
    """
    tmp_severity_string: str = ""

    match severity_format.lower():
        case "letter":
            tmp_severity_string = lvl_to_letter_severity(lvl)
        case "4letter":
            tmp_severity_string = lvl_to_4letter_severity(lvl)
        case "full":
            tmp_severity_string = lvl_to_word_severity(lvl)

    if severity_format.startswith(("LE", "4LE", "FU")):
        return tmp_severity_string.upper()
    if severity_format.startswith(("Le", "4Le", "Fu")):
        return tmp_severity_string.capitalize()
    if severity_format.startswith(("le", "4le", "fu")):
        return tmp_severity_string.lower()

    return default
