# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A fieldgenerator.
"""

import copy
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.generators.builtin_fields import builtin_fields
from clustermanagementtoolkit.generators.get_formatter import get_formatter


# pylint: disable-next=too-many-branches,too-many-locals
def fieldgenerator(view: str | tuple[str, str], selected_namespace: str = "",
                   **kwargs: Any) -> tuple[dict, list[str], str, bool]:
    """
    Generate a dict with the fields necessary for a view.

        Parameters:
            view (str): The view to generate the dict for
            field_index (str): The field_index to use
            field_indexes (dict): A dict with the field indexes to choose between
            fields (dict): The fields to available to the field indexes
            denylist (list[str]): Fields to exclude
        Returns:
            (field_dict, field_names, sortcolumn, sortorder_reverse):
                field_dict (dict): The generated dict
                field_names (list[str]): The fields after pruning using the denylist
                sortcolumn (str): The column to use when sorting
                sortorder_reverse (bool): Should the list be sorted in reverse order
    """
    fields = deep_get(kwargs, DictPath("fields"))
    field_index = deep_get(kwargs, DictPath("field_index"))
    field_indexes = deep_get(kwargs, DictPath("field_indexes"))

    if field_indexes is None or not field_indexes:
        return {}, [], "", False

    field_names = copy.deepcopy(deep_get(field_indexes, DictPath(f"{field_index}#fields"), []))
    sortcolumn = deep_get(field_indexes, DictPath(f"{field_index}#sortcolumn"), "")
    sortorder_reverse = deep_get(field_indexes, DictPath(f"{field_index}#sortorder_reverse"), False)

    denylist = copy.deepcopy(deep_get(kwargs, DictPath("denylist"), []))

    if selected_namespace != "" and "namespace" not in denylist:
        denylist.append("namespace")

    # delete all denylisted fields
    for field in denylist:
        try:
            field_names.remove(field)
        except ValueError:
            pass

    # OK, we've pruned the denylisted fields; now we need to check
    # whether the sort column still applies, and if not try to pick
    # another sortcolumn.
    if not sortcolumn or sortcolumn not in field_names:
        if "name" in field_names:
            sortcolumn = "name"
        elif "namespace" in field_names:
            sortcolumn = "namespace"
        else:
            sortcolumn = field_names[0]

    field_dict = {}
    for field in field_names:
        if field in fields:
            field_dict[field] = deep_get(fields, DictPath(field), {})
        elif field in builtin_fields:
            field_dict[field] = deep_get(builtin_fields, DictPath(field), {})
        else:
            msg = [
                [("fieldgenerator()", "emphasis"),
                 (" called with invalid argument(s):", "error")],
                [("View ", "default"),
                 (f"{view}", "argument"),
                 (": field “", "default"),
                 (f"{field}", "argument"),
                 ("“ cannot be found in view or builtin_fields", "default")],
                [(f"View fields: {fields}", "default")],
                [(f"field_names: {field_names}", "default")],
            ]

            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(msg)

            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   formatted_msg=formatted_msg)

    tmp_fields = {}

    for field_name, field in field_dict.items():
        # This is a custom field, so we need to construct one that's usable here.
        tmp_fields[field_name] = copy.deepcopy(field)

        if (tmp_field := get_formatter(field)) is None:
            continue

        for key, value in tmp_field.items():
            tmp_fields[field_name][key] = value
        tmp_fields[field_name]["sortkey1"] = field_name
        # If sortkey1 == sortcolumn this "fails", but it is good enough.
        tmp_fields[field_name]["sortkey2"] = sortcolumn

    return tmp_fields, field_names, sortcolumn, sortorder_reverse
