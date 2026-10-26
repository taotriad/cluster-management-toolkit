# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Update the list of supported kinds.
"""

from clustermanagementtoolkit import kubernetes_resources


# Maybe this should be moved to kubernetes_resources?
def update_api_status(kind: tuple[str, str], listview: bool = False,
                      infoview: bool = False, local: bool = False) -> None:
    """
    Update kubernetes_resources for a kind to indicate
    whether or not there are list and infoviews for them.

        Parameters:
            kind ((kind, api_group)): The kind tuple
            listview (bool): Does this kind have a list view
            infoview (bool): Does this kind have an info view
            local (bool): The view is a local addition
        Raises:
            TypeError: kind is not a (str, str) tuple
    """
    if not isinstance(kind, tuple) or isinstance(kind, tuple) \
            and not (len(kind) == 2 and isinstance(kind[0], str) and isinstance(kind[1], str)):
        raise TypeError("kind must be (str, str)")
    if not ((listview is None or isinstance(listview, bool))
            and (infoview is None or isinstance(infoview, bool))
            and (local is None or isinstance(local, bool))):
        raise TypeError("listview, infoview, and local must be either None or bool")

    # There are other kind of views than just Kubernetes APIs; just ignore them
    if kind not in kubernetes_resources.kubernetes_resources:
        return
    kubernetes_resources.kubernetes_resources[kind]["list"] = listview
    kubernetes_resources.kubernetes_resources[kind]["info"] = infoview
    kubernetes_resources.kubernetes_resources[kind]["local"] = local
