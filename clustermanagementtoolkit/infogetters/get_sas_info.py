# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_set
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals
def get_sas_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Service Account secrets.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _obj (dict): The dict to extract data from
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            ([dict]): A list with info
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    obj = deep_get(kwargs, DictPath("_obj"))
    info: list[dict] = []

    if obj is None:
        return []

    saname = deep_get(obj, DictPath("metadata#name"))
    sanamespace = deep_get(obj, DictPath("metadata#namespace"))

    for secret in deep_get(obj, DictPath("imagePullSecrets"), []):
        snamespace = deep_get(secret, DictPath("namespace"),
                              deep_get(obj, DictPath("metadata#namespace")))
        secret_name = deep_get(secret, DictPath("name"))

        # Get a reference to the secret
        ref = kh.get_ref_by_kind_name_namespace(("Secret", ""), secret_name,
                                                snamespace, resource_cache=kh_cache)
        deep_set(ref, DictPath("kind"), "Secret", create_path=True)
        deep_set(ref, DictPath("apiVersion"), "", create_path=True)

        info.append({
            "name": secret_name,
            "ref": ref,
            "namespace": snamespace,
            "kind": ("Secret", ""),
            "type": "Image Pull",
        })

    vlist, _status = kh.get_list_by_kind_namespace(("RoleBinding", "rbac.authorization.k8s.io"),
                                                   "", resource_cache=kh_cache)

    # There are other resources we could add reverse entries for, but let's keep things simple.

    # Get all Role Bindings that bind to this ServiceAccount
    for ref in vlist:
        deep_set(ref, DictPath("kind"), "RoleBinding", create_path=True)
        deep_set(ref, DictPath("apiVersion"), "rbac.authorization.k8s.io/", create_path=True)
        for subject in deep_get(ref, DictPath("subjects"), []):
            subjectkind = deep_get(subject, DictPath("kind"), "")
            subjectname = deep_get(subject, DictPath("name"), "")
            subjectnamespace = deep_get(subject, DictPath("namespace"), "")
            if subjectkind == "ServiceAccount" \
                    and subjectname == saname and subjectnamespace == sanamespace:
                info.append({
                    "name": deep_get(ref, DictPath("metadata#name")),
                    "ref": ref,
                    "namespace": deep_get(ref, DictPath("metadata#namespace")),
                    "kind": ("RoleBinding", "rbac.authorization.k8s.io"),
                    "type": "<unset>",
                })

                # Excellent, we have a Role Binding, now add the role it binds to
                rolerefkind = (deep_get(ref, DictPath("roleRef#kind"), ""),
                               deep_get(ref, DictPath("roleRef#apiGroup")))
                rolerefname = deep_get(ref, DictPath("roleRef#name"), "")
                rolerefnamespace = deep_get(ref, DictPath("metadata#namespace"), "")
                roleref = kh.get_ref_by_kind_name_namespace(rolerefkind, rolerefname,
                                                            rolerefnamespace,
                                                            resource_cache=kh_cache)
                if roleref is not None:
                    deep_set(roleref, DictPath("kind"), rolerefkind[0], create_path=True)
                    deep_set(roleref, DictPath("apiVersion"), f"{rolerefkind[1]}/",
                             create_path=True)
                info.append({
                    "name": rolerefname,
                    "ref": roleref,
                    "namespace": subjectnamespace,
                    "kind": rolerefkind,
                    "type": "<unset>",
                })
                break

    vlist, _status = \
        kh.get_list_by_kind_namespace(("ClusterRoleBinding", "rbac.authorization.k8s.io"), "",
                                      resource_cache=kh_cache)

    # Get all Cluster Role Bindings that bind to this ServiceAccount
    for ref in vlist:
        deep_set(ref, DictPath("kind"), "ClusterRoleBinding", create_path=True)
        deep_set(ref, DictPath("apiVersion"), "rbac.authorization.k8s.io/", create_path=True)
        for subject in deep_get(ref, DictPath("subjects"), []):
            subjectkind = deep_get(subject, DictPath("kind"), "")
            subjectname = deep_get(subject, DictPath("name"), "")
            subjectnamespace = deep_get(subject, DictPath("namespace"), "")
            if subjectkind == "ServiceAccount" \
                    and subjectname == saname and subjectnamespace == sanamespace:
                info.append({
                    "name": deep_get(ref, DictPath("metadata#name")),
                    "ref": ref,
                    "namespace": deep_get(ref, DictPath("metadata#namespace")),
                    "kind": ("ClusterRoleBinding", "rbac.authorization.k8s.io"),
                    "type": "<unset>",
                })

                # Excellent, we have a Cluster Role Binding, now add the role it binds to
                rolerefkind = (deep_get(ref, DictPath("roleRef#kind"), ""),
                               deep_get(ref, DictPath("roleRef#apiGroup")))
                rolerefname = deep_get(ref, DictPath("roleRef#name"), "")
                roleref = kh.get_ref_by_kind_name_namespace(rolerefkind, rolerefname,
                                                            subjectnamespace,
                                                            resource_cache=kh_cache)
                if roleref is not None:
                    deep_set(roleref, DictPath("kind"), rolerefkind[0], create_path=True)
                    deep_set(roleref, DictPath("apiVersion"), f"{rolerefkind[1]}/",
                             create_path=True)
                info.append({
                    "name": rolerefname,
                    "ref": roleref,
                    "namespace": subjectnamespace,
                    "kind": rolerefkind,
                    "type": "<unset>",
                })
                break

    return info
