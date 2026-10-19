# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get data for fields in a list; typically used to populate _extra_data.
"""

from collections.abc import Callable

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.fieldgetters.fieldgetter_api_server_version import fieldgetter_api_server_version  # noqa: E501
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.fieldgetters.fieldgetter_executable_version import fieldgetter_executable_version  # noqa: E501
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.fieldgetters.fieldgetter_kubernetes_object_version import fieldgetter_kubernetes_object_version  # noqa: E501


# Fieldgetters acceptable for direct use in view files
fieldgetter_allowlist: dict[str, Callable] = {
    "fieldgetter_api_server_version": fieldgetter_api_server_version,
    "fieldgetter_executable_version": fieldgetter_executable_version,
    "fieldgetter_kubernetes_object_version": fieldgetter_kubernetes_object_version,
}
