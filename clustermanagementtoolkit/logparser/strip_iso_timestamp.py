# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.cmtlib import none_timestamp

from clustermanagementtoolkit.logparser.split_iso_timestamp import split_iso_timestamp


def strip_iso_timestamp(message: str) -> str:
    """
    Given a string with a timestamp, return that string without the timestamp.

        Parameters:
            message (str): The message to strip
        Returns:
            (str): The stripped message
    """
    _timestamp, message = split_iso_timestamp(message, none_timestamp())
    return message
