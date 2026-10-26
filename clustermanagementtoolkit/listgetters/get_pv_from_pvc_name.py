# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the Persistent Volume for a Persistent Volume Claim.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


def get_pv_from_pvc_name(pvc_name: str, **kwargs: Any) -> tuple[dict[str, Any], str]:
    """
    Given the name of a Persistent Volume Claim,
    return the corresponding PersistentVolume.

        Parameters:
            pvc_name (str): The name of the Persistent Volume Claim
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            ((dict[str, Any], str)):
                (dict[str, Any]): Persistent Volume object
                (str): The name of the Persistent Volume.
        Raises:
            ProgrammingError: Function called without kubernetes_helper
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    pv: dict[str, Any] = {}
    pv_name: str = ""
    field_selector = f"metadata.name={pvc_name}"

    vlist, status = kh.get_list_by_kind_namespace(("PersistentVolumeClaim", ""), "",
                                                  field_selector=field_selector,
                                                  resource_cache=kh_cache)
    if status == 200:
        for pvc in vlist:
            if deep_get(pvc, DictPath("metadata#name")) == pvc_name:
                volume_name = deep_get(pvc, DictPath("spec#volumeName"), "")
                if volume_name:
                    pv_name = volume_name
                    pv = kh.get_ref_by_kind_name_namespace(("PersistentVolume", ""),
                                                           pv_name, None, resource_cache=kh_cache)
                    break

    return pv, pv_name
