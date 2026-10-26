# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Asynchronous listgetters acceptable for direct use in view files.
"""

from collections.abc import Callable

from clustermanagementtoolkit.listgetters_async.get_context_list import get_context_list
from clustermanagementtoolkit.listgetters_async.get_inventory_list import get_inventory_list
from clustermanagementtoolkit.listgetters_async.get_kubernetes_list import get_kubernetes_list

listgetter_async_allowlist: dict[str, Callable] = {
    # Used by listpad
    "get_context_list": get_context_list,
    "get_inventory_list": get_inventory_list,
    "get_kubernetes_list": get_kubernetes_list,
}
