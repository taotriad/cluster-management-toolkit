# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to compact lists of integers into ranges.
"""

from typing import Any

from natsort import natsorted

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-branches
def get_obj_ranges(obj: dict, path: list[DictPath], values: list[Any]) -> list[Any]:
    """
    A helper for get_obj() that compacts a list of integers into a list of integer ranges.

        Parameters:
            obj (dict): The object to extract data from
            path ([DictPath]): A path with fallbacks
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
    """
    rawvals = []
    for p in path:
        tmp = deep_get(obj, DictPath(p))
        if tmp is not None:
            rawvals += tmp
    rangevals = []
    if tmp is not None:
        firstnum = None
        lastnum = None
        sortedvals = natsorted(tmp)
        for sortedval in sortedvals:
            # The range is sorted; this means that we add everything as is except
            # None until we reach the first numerical, create ranges for
            # the numericals, then add everything as is except None until the end
            if sortedval is None:
                continue
            # pylint: disable-next=unidiomatic-typecheck
            if type(sortedval) == int:  # noqa: E721
                if firstnum is None:
                    firstnum = sortedval
                else:
                    if lastnum is None or sortedval == lastnum + 1:
                        lastnum = sortedval
                    else:
                        # Flush and start a new range
                        rangevals.append((f"{firstnum}", f"{lastnum}", ""))
                        firstnum = sortedval
                        lastnum = None
            else:
                if firstnum is not None:
                    if lastnum is None:
                        rangevals.append((f"{firstnum}", "", ""))
                    else:
                        rangevals.append((f"{firstnum}", f"{lastnum}", ""))
                        lastnum = None
                    firstnum = None
                rangevals.append(("", "", sortedval))
        if firstnum is not None:
            if lastnum is None:
                rangevals.append((f"{firstnum}", "", ""))
            else:
                rangevals.append((f"{firstnum}", f"{lastnum}", ""))

    values.append((rangevals, "raw"))
    return values
