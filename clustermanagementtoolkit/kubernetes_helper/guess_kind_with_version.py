# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given an incomplete kind (no API-group) guess its full (kind, API-version) tuple.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper.guess_kind import guess_kind

from clustermanagementtoolkit import kubernetes_resources


def guess_kind_with_version(kind: str | tuple[str, str]) -> tuple[str, str]:
    """
    A wrapper around guess_kind() that, if a lookup is successful,
    returns the api_family with the latest supported version.

        Parameters:
            kind (str):
                kind (str): The Kubernetes kind
            kind ((str, str)):
                kind (str): The API-name
                api_group (str): The API-group
        Returns:
            (str, str):
                (str): The Kubernetes kind
                (str): The API-group
        Raises:
            NameError: No matching API could be found
            TypeError: kind is not a str or (str, str) tuple
    """
    kind = guess_kind(kind)

    newest_api_path = deep_get(kubernetes_resources.kubernetes_resources[kind],
                               DictPath("api_paths"))[0]
    # This is for core APIs.
    newest_api_path = newest_api_path.removeprefix("api/")
    # This is for all APIs.
    newest_api_path = newest_api_path.removesuffix("/")
    # This is for non-core APIs.
    newest_api_path = newest_api_path.removeprefix("apis/")

    return (kind[0], newest_api_path)
