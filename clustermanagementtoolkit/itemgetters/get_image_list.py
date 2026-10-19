# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import sys
from typing import Any, cast

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmtlib import disksize_to_human


def get_image_list(obj: dict, **kwargs: Any) -> list[tuple[str, str]]:
    """
    Get a list of container images.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the image list
        Returns:
            ([dict]): A list of container images
    """
    vlist = []
    path = deep_get(kwargs, DictPath("path"))

    for image in deep_get(obj, DictPath(path), []):
        name = ""
        for name in deep_get(image, DictPath("names"), []):
            # This is the preferred name
            if "@sha256:" not in name:
                break

        if not name:
            continue
        size = disksize_to_human(deep_get(image, DictPath("sizeBytes"), "0"))
        vlist.append((name, size))
    return cast(list[tuple[str, str]], natsorted(vlist))
