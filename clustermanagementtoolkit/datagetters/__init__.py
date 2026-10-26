# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Datagetters are used for data extraction that is too complex
to be expressed through parameters to generic_infogetter().
"""

from collections.abc import Callable

# pylint: disable=line-too-long
from clustermanagementtoolkit.datagetters.datagetter_api_support import datagetter_api_support
from clustermanagementtoolkit.datagetters.datagetter_container_status import datagetter_container_status  # noqa: E501
from clustermanagementtoolkit.datagetters.datagetter_container_status import get_container_status  # noqa: E501
from clustermanagementtoolkit.datagetters.datagetter_deprecated_api import datagetter_deprecated_api
from clustermanagementtoolkit.datagetters.datagetter_endpoint_ips import datagetter_endpoint_ips
from clustermanagementtoolkit.datagetters.datagetter_eps_endpoints import datagetter_eps_endpoints
from clustermanagementtoolkit.datagetters.datagetter_eps_endpoints import get_endpointslices_endpoints  # noqa: E501
from clustermanagementtoolkit.datagetters.datagetter_latest_version import datagetter_latest_version
from clustermanagementtoolkit.datagetters.datagetter_metrics import datagetter_metrics
from clustermanagementtoolkit.datagetters.datagetter_pod_status import datagetter_pod_status
from clustermanagementtoolkit.datagetters.datagetter_pod_status import get_pod_status
# pylint: enable=line-too-long

# Datagetters acceptable for direct use in view files
datagetter_allowlist: dict[str, Callable] = {
    "datagetter_api_support": datagetter_api_support,
    "datagetter_container_status": datagetter_container_status,
    "datagetter_deprecated_api": datagetter_deprecated_api,
    "datagetter_endpoint_ips": datagetter_endpoint_ips,
    "datagetter_eps_endpoints": datagetter_eps_endpoints,
    "datagetter_latest_version": datagetter_latest_version,
    "datagetter_metrics": datagetter_metrics,
    "datagetter_pod_status": datagetter_pod_status,
    "get_container_status": get_container_status,
    "get_endpointslices_endpoints": get_endpointslices_endpoints,
    "get_pod_status": get_pod_status,
}
