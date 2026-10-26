# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate an argument.
"""

import sys
from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath
from clustermanagementtoolkit.cmttypes.deep_get import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ArgumentValidationError


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def validate_args(kwargs_spec: dict[str, Any], kwargs: Any) -> None:
    """
    Validates that the kwargs against the requirements in kwargs_spec.

        Parameters:
            kwargs_spec ([dict]): The expected properties for kwargs
            kwargs ([{str, Any}]): The kwargs to validate
        Raises:
            ArgumentValidationError (with subexception)
    """
    results: dict = {}
    msg: list[list[tuple[str, str]]] = []
    function: str = "<unknown>"  # This is just to make pylint happy
    subexception = None

    try:
        # This is to get the necessary stack info
        raise UserWarning
    except UserWarning:
        frame = sys.exc_info()[2].tb_frame.f_back  # type: ignore
        function = str(frame.f_code.co_name)  # type: ignore

    anyof = deep_get(kwargs_spec, DictPath("__anyof"), ())
    allof = deep_get(kwargs_spec, DictPath("__allof"), ())
    if not (isinstance(anyof, tuple) and isinstance(allof, tuple)
            and isinstance(kwargs_spec, dict) and isinstance(kwargs, dict)):
        msg = [
            [("validate_arguments()", "emphasis"),
             (" called with invalid argument(s):", "error")],
            [("    __anyof", "argument"), (" is ", "default"), (f"{type(anyof)}", "argument"),
             (" expected ", "default"), (f"{tuple!r}", "emphasis")],
            [("    __allof", "argument"), (" is ", "default"), (f"{type(allof)}", "argument"),
             (" expected ", "default"), (f"{tuple!r}", "emphasis")],
            [("    kwargs_spec", "argument"), (" is ", "default"),
             (f"{type(kwargs_spec)}", "argument"),
             (" expected ", "default"), (f"{dict!r}", "emphasis")],
            [("    kwargs", "argument"), (" is ", "default"), (f"{type(kwargs)}", "argument"),
             (" expected ", "default"), (f"{dict!r}", "emphasis")],
        ]

        raise ArgumentValidationError(subexception=TypeError, formatted_msg=msg)

    for key, data in kwargs_spec.items():
        if key.startswith("__"):
            continue
        expected_types = deep_get(data, DictPath("types"))
        none_acceptable = deep_get(data, DictPath("none"), False)
        # -1 (no min/max length); min_len == max_len for exact length

        min_max = deep_get(data, DictPath("range"))
        kwarg = deep_get(kwargs, DictPath(key))
        # pylint: disable-next=too-many-boolean-expressions
        if (expected_types is None or not isinstance(expected_types, tuple)
            or not isinstance(none_acceptable, bool)
            or (min_max is not None
                and (not isinstance(min_max, tuple) or len(min_max) != 2
                     or not (min_max[0] is None or isinstance(min_max[0], (int, float)))
                     or not (min_max[1] is None or isinstance(min_max[1], (int, float)))))):
            msg = [
                [("validate_arguments()", "emphasis"),
                 (" called with invalid argument(s):", "error")],
                [("    types", "argument"),
                 (" is ", "default"),
                 (f"{type(expected_types)}", "argument"),
                 (" expected ", "default"),
                 (f"{tuple!r}", "emphasis")],
                [("    none", "argument"),
                 (" is ", "default"),
                 (f"{type(none_acceptable)}", "argument"),
                 (" expected ", "default"),
                 (f"{bool!r}", "emphasis")],
                [("    range", "argument"),
                 (" is ", "default"),
                 (f"{type(min_max)}", "argument"),
                 (" expected ", "default"),
                 ("((int|float, int|float))", "emphasis")],
            ]

            raise ArgumentValidationError(subexception=TypeError, formatted_msg=msg)

        if kwarg is None and not none_acceptable:
            if len(expected_types) == 1:
                results[key] = {
                    "subexception": TypeError,
                    "msg": [(f"    {key}", "argument"),
                            (" is ", "default"),
                            ("None", "emphasis"),
                            (" expected ", "default"),
                            (f"{expected_types}", "emphasis")],
                    "missing": True,
                }
            else:
                results[key] = {
                    "subexception": TypeError,
                    "msg": [(f"    {key}", "argument"),
                            (" is ", "default"),
                            ("None", "emphasis"),
                            (" expected one of ", "default"),
                            (f"{expected_types}", "emphasis")],
                    "missing": True,
                }
            # If kwarg is None there's nothing else we can check
            continue

        if not isinstance(kwarg, expected_types):
            if len(expected_types) == 1:
                results[key] = {
                    "subexception": TypeError,
                    "msg": [(f"    {key}", "argument"),
                            (" is ", "default"),
                            (f"{type(kwarg)}", "emphasis"),
                            (" expected ", "default"),
                            (f"{expected_types}", "emphasis")],
                }
            else:
                results[key] = {
                    "subexception": TypeError,
                    "msg": [(f"    {key}", "argument"), (" is ", "default"),
                            (f"{type(kwarg)}", "emphasis"), (" expected one of ", "default"),
                            (f"{expected_types}", "emphasis")],
                }
            continue

        if min_max is not None:
            minval, maxval = min_max
            if minval is None:
                minval_cmp = -sys.maxsize
                minval_str = ""
            else:
                minval_cmp = minval
                minval_str = str(minval)
            if maxval is None:
                maxval_cmp = sys.maxsize
                maxval_str = ""
            else:
                maxval_cmp = maxval
                maxval_str = str(maxval)

            if isinstance(kwarg, (int, float)):
                if not minval_cmp <= kwarg <= maxval_cmp:
                    results[key] = {
                        "subexception": ValueError,
                        "msg": [(f"    {key}", "argument"),
                                ("=", "default"),
                                (f"{kwarg}", "emphasis"),
                                (", valid range is [", "default"),
                                (f"{minval_str}", "numerical"),
                                (", ", "default"),
                                (f"{maxval_str}", "numerical"),
                                ("]", "default")],
                    }
                    continue
            else:
                if not minval_cmp <= len(kwarg) <= maxval_cmp:
                    results[key] = {
                        "subexception": ValueError,
                        "msg": [("    len(", "default"), (f"{key}", "argument"), (")=", "default"),
                                (f"{len(kwarg)}", "emphasis"), (", valid range is [", "default"),
                                (f"{minval_str}", "numerical"), (", ", "default"),
                                (f"{maxval_str}", "numerical"), ("]", "default")],
                    }
                    continue
        results[key] = {}

    # Check if we got all the arguments we asked for
    missing: list[str] = []
    anyexists: bool = False

    for key in anyof:
        if key in kwargs:
            anyexists = True
            break
    if anyof and not anyexists:
        msg = [
            [(f"{function}()", "emphasis"), (" called with invalid argument(s):", "error")],
            [("    At least one of the following arguments must be present:", "default")],
        ]
        for key in anyof:
            msg.append([(f"{key}", "argument")])
        subexception = ValueError

    for key in allof:
        if key not in kwargs:
            missing += key
    if missing:
        msg = [
            [(f"{function}()", "emphasis"), (" called with invalid argument(s):", "error")],
            [("    The following arguments are missing but must be present:", "default")],
        ]
        for key in missing:
            msg.append([(f"{key}", "argument")])
        subexception = ValueError

    if not msg:
        # Check whether arguments were OK
        for key, result in results.items():
            # No complaints
            if not result:
                continue
            submsg = deep_get(result, DictPath("msg"))
            subexception = deep_get(result, DictPath("subexception"), TypeError)
            if not msg:
                msg = [
                    [(f"{function}()", "emphasis"),
                     (" called with invalid argument(s):", "error")],
                ]
            msg.append(submsg)

    if msg:
        raise ArgumentValidationError(subexception=subexception, formatted_msg=msg)
