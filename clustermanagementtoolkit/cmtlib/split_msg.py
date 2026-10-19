# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re

from clustermanagementtoolkit.cmtlib.replace_newlines import replace_newlines


def split_msg(rawmsg: str) -> list[str]:
    """
    Split a string into a list of strings, strip NUL-bytes, and convert newlines.

        Parameters:
            rawmsg (str): The string to split
        Returns:
            ([str]): A list of split strings
    """
    if not isinstance(rawmsg, str):
        raise TypeError(f"rawmsg is type {type(rawmsg)}, expected str")
    # We only want "\n" to represent newlines
    tmp = replace_newlines(rawmsg, policy="keep")
    # We also replace all \x00 with <NUL>
    tmp = tmp.replace("\x00", "<NUL>")
    # We also replace non-breaking space with space
    tmp = tmp.replace("\xa0", " ")
    # And remove almost all control characters
    tmp = re.sub(r"[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f-\x9f]", "\uFFFD", tmp)

    return list(map(str.rstrip, tmp.splitlines()))
