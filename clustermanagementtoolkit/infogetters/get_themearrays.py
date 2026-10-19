# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any


# pylint: disable-next=unused-argument
def get_themearrays(obj: dict, **kwargs: Any) -> dict:
    """
    This is effectively a noop, but we need to have an infogetter.

        Parameters:
            obj (dict): The themearrays object
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            (dict): The themearrays
    """
    return obj
