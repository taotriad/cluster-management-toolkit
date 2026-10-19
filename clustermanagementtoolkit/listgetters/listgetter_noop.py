# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A listgetter that returns an empty list.
"""

from typing import Any


# pylint: disable-next=unused-argument
def listgetter_noop(obj: dict, **kwargs: Any) -> tuple[list, str]:
    """
    A noop listgetter that returns an empty list.

        Parameters:
            obj (dict): The object to extract data from [unused]
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([], str):
                ([]): An empty list
                (str): Always "OK"
    """
    return [], "OK"
