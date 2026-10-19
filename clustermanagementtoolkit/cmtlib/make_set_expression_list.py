# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


EXPRESSION_LOOKUP: dict[str, Any] = {
    "In": {
        "pretty_operator": "In ",
        "required_values": "1+",
    },
    "NotIn": {
        "pretty_operator": "Not In ",
        "required_values": "1+",
    },
    "Equal": {
        "pretty_operator": "= ",
        "required_values": "1+",
    },
    "Exists": {
        "pretty_operator": "Exists",
        "required_values": "0",
    },
    "InRegexp": {
        "pretty_operator": "In Regexp",
        "required_values": "1+",
    },
    "IsFalse": {
        "pretty_operator": "Is False",
        "required_values": "0",
    },
    "IsTrue": {
        "pretty_operator": "Is True",
        "required_values": "0",
    },
    "DoesNotExist": {
        "pretty_operator": "Does Not Exist",
        "required_values": "0",
    },
    "Ge": {
        "pretty_operator": ">= ",
        "required_values": "1",
    },
    "Gt": {
        "pretty_operator": "> ",
        "required_values": "1",
    },
    "Le": {
        "pretty_operator": "=< ",
        "required_values": "1",
    },
    "GtLt": {
        "pretty_operator": "<> ",
        "required_values": "2",
    },
    "GeLe": {
        "pretty_operator": ">< ",
        "required_values": "2",
    },
    "Lt": {
        "pretty_operator": "< ",
        "required_values": "1",
    }
}


# pylint: disable-next=too-many-branches,too-many-statements,too-many-locals
def make_set_expression_list(expression_list: list[dict[str, Any]], **kwargs: Any) \
        -> list[tuple[str, str, str] | tuple[str, str, str, str, str]]:
    """
    Create a list of match expressions (key, operator, values)
    or tolerations {key, operator, values, effect}.

        Parameters:
            expression_list ([dict]): A list of dicts to extract extract the data from
            **kwargs (dict[str, Any]): Keyword arguments
                key: str = "All",
                operator_paths: list[DictPath] | None = None,
                key_paths: list[DictPath] | None = None,
                values_paths: list[DictPath] | None = None,
                effect_paths: list[DictPath] | None = None,
                timeout_paths: list[DictPath] | None = None,
                is_toleration (bool): Is this a match expression or a toleration?
        Returns:
            ([(key, operator, values)]): A set expression list
    """
    expressions: list[tuple[str, str, str] | tuple[str, str, str, str, str]] = []
    is_toleration: bool = deep_get(kwargs, DictPath("is_toleration"), False)
    key: str = deep_get(kwargs, DictPath("key"), "All")
    operator_paths: list[DictPath] = deep_get(kwargs, DictPath("operator_paths"),
                                              [DictPath("operator"), DictPath("op")])
    key_paths: list[DictPath] = deep_get(kwargs, DictPath("key_paths"),
                                         [DictPath("key"), DictPath("scopeName")])
    values_paths: list[DictPath] = deep_get(kwargs, DictPath("values_paths"),
                                            [DictPath("values"), DictPath("value")])
    effect_paths: list[DictPath] = deep_get(kwargs, DictPath("effect_paths"),
                                            [DictPath("effect")])
    timeout_paths: list[DictPath] = deep_get(kwargs, DictPath("timeout_paths"),
                                             [DictPath("timeout")])

    if expression_list is not None:
        if not isinstance(expression_list, list):
            raise TypeError("expression_list must be a list")
        for expression in expression_list:
            operator = deep_get_with_fallback(expression, operator_paths)
            new_key = deep_get_with_fallback(expression, key_paths, key)
            tmp_values = deep_get_with_fallback(expression, values_paths, [])
            if tmp_values and isinstance(tmp_values, str):
                tmp_values = [tmp_values]
            if not isinstance(tmp_values, list):
                raise TypeError("values must be a string or list; "
                                f"{tmp_values} is of type {type(tmp_values)}")

            if not new_key:
                new_key = "All"
                if operator != "Exists":
                    raise ValueError("When key is unset or empty operator must be 'Exists'")
            if not operator:
                if not tmp_values:
                    operator = "Exists"
                else:
                    operator = "Equal"
            if not isinstance(operator, str):
                raise TypeError(f"Operator {operator} is type: {type(operator)}, expected str")
            if operator not in EXPRESSION_LOOKUP:
                raise ValueError(f"Unknown operator '{operator}'")
            if not isinstance(new_key, str):
                raise TypeError(f"Key {new_key} is type: {type(new_key)}, expected str")
            pretty_operator = deep_get(EXPRESSION_LOOKUP, DictPath(f"{operator}#pretty_operator"))
            required_values = deep_get(EXPRESSION_LOOKUP, DictPath(f"{operator}#required_values"))

            # While all documentation seems to indicate that Equal requires a value,
            # reality disagrees.
            if operator == "Equal" and not tmp_values:
                tmp_values = ["<empty>"]

            if required_values == "0" and tmp_values and len(max(tmp_values, key=len)):
                # Exists and DoesNotExist do no accept values;
                # for the sake of convenience we still accept empty values
                raise ValueError(f"operator {operator} does not accept values; "
                                 f"values {tmp_values}")
            if required_values == "1" and len(tmp_values) != 1:
                raise ValueError(f"operator {operator} requires exactly 1 value; "
                                 f"values {tmp_values}")
            if required_values == "1+" and len(tmp_values) < 1:
                raise ValueError(f"operator {operator} requires at least 1 value; "
                                 f"values {tmp_values}")
            values = ", ".join(tmp_values)
            if required_values != "0" and operator not in ("Equal", "Gt", "Lt"):
                values = f"[{values}]"

            if is_toleration:
                effect = deep_get_with_fallback(expression, effect_paths, "All")
                toleration_timeout = deep_get_with_fallback(expression, timeout_paths,
                                                            "Never", fallback_on_empty=True)
                toleration_timeout = str(toleration_timeout)
                try:
                    if int(toleration_timeout) <= 0:
                        toleration_timeout = "Immediately"
                except ValueError:
                    pass
                expressions.append((new_key, pretty_operator, values, effect, toleration_timeout))
            else:
                # Toleration timeout can either be time in seconds,
                # Immediately, or Never
                expressions.append((new_key, pretty_operator, values))
    return expressions
