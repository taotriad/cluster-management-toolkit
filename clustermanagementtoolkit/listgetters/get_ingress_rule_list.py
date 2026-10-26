# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of Ingress rules.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=unused-argument
def get_ingress_rule_list(obj: dict, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Listgetter for Ingress rules.

        Parameters:
            obj (Dict): The object to extract ingress rule information from
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            (([dict], int)):
                ([dict[str, Any]]): The ingress rules
                (int): The status for the request
    """
    vlist: list[dict[str, Any]] = []
    status: int = 200

    for item in deep_get(obj, DictPath("spec#rules"), []):
        host: str = deep_get(item, DictPath("host"), "*")

        if deep_get(item, DictPath("http")) is not None:
            for path in deep_get(item, DictPath("http#paths")):
                rpath: str = deep_get(path, DictPath("path"), "")
                path_type: str = deep_get(path, DictPath("pathType"), "")
                backend_kind: tuple[str, str] | None = None
                name: str = ""
                port: tuple[str, str] = ("", "")

                if "service" in deep_get(path, DictPath("backend"), {}):
                    backend_kind = ("Service", "")
                    name = deep_get(path, DictPath("backend#service#name"), "")
                    port = (deep_get(path, DictPath("backend#service#port#number"), ""),
                            deep_get(path, DictPath("backend#service#port#name"), ""))
                elif "resource" in deep_get(path, DictPath("backend"), {}):
                    backend_kind = (deep_get(path, DictPath("backend#resource#kind"), ""),
                                    deep_get(path, DictPath("backend#resource#apiGroup"), ""))
                    name = deep_get(path, DictPath("backend#resource#name"), "")

                if backend_kind:
                    vlist.append({
                        "host": host,
                        "path": rpath,
                        "path_type": path_type,
                        "backend_kind": backend_kind,
                        "name": name,
                        "port": port,
                    })

    return vlist, status
