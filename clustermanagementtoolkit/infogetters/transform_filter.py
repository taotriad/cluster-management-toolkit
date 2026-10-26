# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A filter that applies transformations on values.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def transform_filter(value: DictPath, transformations: dict) -> Any:
    """
    Given a transformation dictionary,
    look up and return the corresponding value.

        Parameters:
            value (DictPath): The value to look up
            transformations (dict[str, Any]): The transformation dictionary
        Returns:
            (Any): The transformed value
    """
    if transformations and value in transformations:
        value = deep_get(transformations, value)
    return value
