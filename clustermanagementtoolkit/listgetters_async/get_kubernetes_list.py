# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Asynchronous listgetter for Kubernetes objects.
"""

from collections.abc import Callable
import sys
from typing import Any
import uuid

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_set
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit import infogetters

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.listgetters_async.listgetter_async_postprocessor_allowlist import listgetter_async_postprocessor_allowlist  # noqa: E501


# pylint: disable-next=unused-argument,disable-next=too-many-locals
def get_kubernetes_list(*args: Any,
                        **kwargs: Any) -> tuple[list[Any], int | str | list[StatusGroup]]:
    """
    Fetch a list of Kubernetes objects, optionally with postprocessing.

        Parameters:
            *args [Any]: Positional arguments (unused)
            **kwargs (dict[str, Any]): Keyword arguments
                kind ((str, str)): The Kubernetes kind (required)
                namespace (str): The Kubernetes namespace (optional)
                label_selector (str): A label selector (optional)
                field_selector (str): A field selector (optional)
                fetch_args (dict): Specific arguments (optional)
                    sort_key (str): The sort-key to use if sorting the list (optional)
                    sort_reverse (bool): Should the list be returned
                                         with reversed sort order? (optional)
                    postprocess (str): Post-processing (if any) to apply (optional)
                    limit (int): The max number of items to return (optional)
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            ([dict], int|str|[StatusGroup]):
                ([dict]): A list of Kubernetes objects
                (int|str|[StatusGroup]): Server status (int),
                                         unused (str),
                                         or the individual StatusGroup for all objects
        Raises:
            ProgrammingError: Function called without kubernetes_helper
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    kind = deep_get(kwargs, DictPath("kind"))
    namespace = deep_get(kwargs, DictPath("namespace"), "")
    label_selector = deep_get(kwargs, DictPath("label_selector"), "")
    field_selector = deep_get(kwargs, DictPath("field_selector"), "")
    fetch_args = deep_get(kwargs, DictPath("fetch_args"), {})
    sort_key: str = deep_get(fetch_args, DictPath("sort_key"), "")
    sort_reverse: bool = deep_get(fetch_args, DictPath("sort_reverse"), False)
    postprocess: str = deep_get(fetch_args, DictPath("postprocess"), "")
    postprocessor: str | Callable = deep_get(kwargs, DictPath("postprocessor"), "")
    limit = deep_get(fetch_args, DictPath("limit"))
    extra_data = []

    vlist, status = kh.get_list_by_kind_namespace(kind, namespace,
                                                  label_selector=label_selector,
                                                  field_selector=field_selector,
                                                  resource_cache=kh_cache)

    # This will slow things down, but we need to ensure that all resources have a uid.

    for d in vlist:
        if not deep_get(d, DictPath("metadata#uid")):
            deep_set(d, DictPath("metadata#uid"), str(uuid.uuid4()), create_path=True)

    if sort_key:
        vlist = natsorted(vlist,
                          key=lambda x: deep_get(x, DictPath(sort_key), ""), reverse=sort_reverse)
    if postprocess == "node":
        vlist = infogetters.get_node_info(vlist=vlist)
        extra_data = [deep_get(s, DictPath("status_group")) for s in vlist]
    elif postprocess == "pod":
        vlist = infogetters.get_pod_info(vlist=vlist,
                                         in_depth_node_status=False,
                                         kubernetes_helper=kh)
        extra_data = [deep_get(s, DictPath("status_group")) for s in vlist]
    elif callable(postprocessor) or postprocessor in listgetter_async_postprocessor_allowlist:
        if not callable(postprocessor):
            postprocessor = listgetter_async_postprocessor_allowlist[postprocessor]
        vlist, extra_data = postprocessor(vlist=vlist, status=status, **kwargs)
    else:
        extra_data = status
    if limit is not None:
        vlist = vlist[:limit]

    return vlist, extra_data
