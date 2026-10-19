# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit import cmtlib


def __process_string(value: str, quotes: str, newlines: str = "escape") -> str:
    # We do not want any newlines, and extra trailing whitespace
    if value is None:
        value = ""
    if isinstance(value, str):
        value = cmtlib.replace_newlines(value, policy=newlines)
        value = cmtlib.replace_quotes(value, policy=quotes)
    return value
