# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any


def split_match_label_selector(selector: str) -> dict[str, Any]:
    """
    Given a string-representation of a matchLabel selector,
    return a dict-representation.

        Parameters:
            selector (str): A matchLabel selector expressed as a string
        Returns:
            (dict[str, Any]): A matchLabel selector expressed as a dict
        Raises:
            ValueError: Data contained both ":" and "=" as separator
    """
    new_selector: dict[str, Any] = {}

    # If the string contains both : and = we have no idea how to interpret this as a selector.
    if ":" in selector and "=" in selector:
        raise ValueError

    item = ""
    try:
        for item in selector.split(","):
            if "=" in item:
                key, value = item.split("=", maxsplit=1)
            else:
                key, value = item.split(":", maxsplit=1)
            new_selector[key] = value
    except ValueError:
        pass
    return new_selector
