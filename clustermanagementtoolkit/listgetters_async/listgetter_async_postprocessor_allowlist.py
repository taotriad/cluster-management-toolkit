# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Postprocessors acceptable for use in asynchronous listgetters.
"""

from collections.abc import Callable

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.listgetters_async.postprocessor_node_resources import postprocessor_node_resources  # noqa: E501

listgetter_async_postprocessor_allowlist: dict[str, Callable] = {
    "postprocessor_node_resources": postprocessor_node_resources,
}
