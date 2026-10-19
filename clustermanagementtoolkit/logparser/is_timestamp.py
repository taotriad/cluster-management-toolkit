# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re


def is_timestamp(message: str) -> bool:
    """
    Tries to check whether the field is a timestamp.

        Parameters:
            message (str): The string to check
        Returns:
            (bool): True if the string is a timestamp, False if not
    """
    if re.match(r"^\d\.\d+e\+09", message) is not None:
        return True

    return re.match(r"^\d{4}[/-]\d\d[/-]\d\d"
                    r"[ T]"
                    r"\d\d[\.:]\d\d[\.:]\d\d"
                    r"([\.,]\d{3,9} [+-]\d\d[:\.]\d\d|"
                    r"[\.,]\d{3,9}Z?|"
                    r"Z?)$", message) is not None
