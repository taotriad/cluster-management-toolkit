# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-return-statements,too-many-locals,too-many-branches,too-many-statements # noqa: E501
def when_filter(when_path: dict, item: dict, key: str | None = None, value: Any = None) -> bool:
    """
    A filter used by infogetters. Given a dictionary of when-conditions,
    # and either a dict or a key/value pair, return True if all conditions
    # evaluate to true, or False if at least one condition evaluates to false.

        Parameters:
            when_path (dict[str, list[dict[str, Any]]]): A dictionary of when-conditions
            item (dict[str, Any]): An item to filter
            key (str): A key
            value (Any): A value
        Returns:
            (bool): True if all conditions evaluated to True,
                    False if at least one condition evaluated to False
    """
    when_conditions = deep_get(when_path, DictPath("when"), [])

    _key = key
    _value = value

    for when_condition in when_conditions:
        # These apply to the key
        if _key is None:
            key = deep_get(when_condition, DictPath("key"))

        # These do not make sense when using when#key, since we already know the key
        if key is not None:
            when_key_eq = deep_get(when_condition, DictPath("key_eq"))
            when_key_ne = deep_get(when_condition, DictPath("key_ne"))
            when_key_in = deep_get(when_condition, DictPath("key_in"))
            when_key_notin = deep_get(when_condition, DictPath("key_notin"))
            when_key_startswith = deep_get(when_condition, DictPath("key_startswith"))
            when_key_notstartswith = deep_get(when_condition, DictPath("key_notstartswith"))
            when_key_endswith = deep_get(when_condition, DictPath("key_endswith"))
            when_key_notendswith = deep_get(when_condition, DictPath("key_notendswith"))
            if when_key_eq is not None and when_key_eq != key:
                return False
            if when_key_ne is not None and when_key_ne == key:
                return False
            if when_key_in is not None and key not in when_key_in:
                return False
            if when_key_notin is not None and key in when_key_notin:
                return False
            if when_key_startswith is not None and not key.startswith(when_key_startswith):
                return False
            if when_key_notstartswith is not None and key.startswith(when_key_notstartswith):
                return False
            if when_key_endswith is not None and not key.endswith(when_key_endswith):
                return False
            if when_key_notendswith is not None and key.endswith(when_key_notendswith):
                return False

        # Check for none
        if _value is None:
            if isinstance(item, dict):
                if key is None:
                    raise ValueError("item is a dict, but key is None")
                value = deep_get(item, DictPath(key))
            else:
                value = item

        # These check whether the key has a value
        when_none = deep_get(when_condition, DictPath("none"))
        when_notnone = deep_get(when_condition, DictPath("notnone"))

        # All these check the value
        when_eq = deep_get(when_condition, DictPath("eq"))
        when_ne = deep_get(when_condition, DictPath("ne"))
        when_lt = deep_get(when_condition, DictPath("lt"))
        when_lte = deep_get(when_condition, DictPath("lte"))
        when_gt = deep_get(when_condition, DictPath("gt"))
        when_gte = deep_get(when_condition, DictPath("gte"))

        when_in = deep_get(when_condition, DictPath("in"))
        when_notin = deep_get(when_condition, DictPath("notin"))

        when_missing = deep_get(when_condition, DictPath("missing"))
        when_notmissing = deep_get(when_condition, DictPath("notmissing"))

        when_startswith = deep_get(when_condition, DictPath("startswith"))
        when_notstartswith = deep_get(when_condition, DictPath("notstartswith"))
        when_endswith = deep_get(when_condition, DictPath("endswith"))
        when_notendswith = deep_get(when_condition, DictPath("notendswith"))

        # These check dict values
        when_isdict = deep_get(when_condition, DictPath("isdict"))
        when_notisdict = deep_get(when_condition, DictPath("notisdict"))
        when_dicthaskey = deep_get(when_condition, DictPath("dicthaskey"))
        when_notdicthaskey = deep_get(when_condition, DictPath("notdicthaskey"))

        # Check for existance
        if when_missing is not None and when_missing in item:
            return False
        if when_notmissing is not None and when_notmissing not in item:
            return False

        if when_notnone is not None and value is None:
            return False
        if when_none is not None and value is not None:
            return False

        # dict-based checks
        if when_isdict is not None and not isinstance(value, dict):
            return False
        if when_notisdict is not None and isinstance(value, dict):
            return False
        if when_dicthaskey is not None \
                and (value is None
                     or (not isinstance(value, dict) or when_dicthaskey not in value)):
            return False
        if when_notdicthaskey is not None \
                and (value is not None
                     and (not isinstance(value, dict) or when_notdicthaskey in value)):
            return False

        # Set-based checks
        if when_in is not None and value not in when_in:
            return False
        if when_notin is not None and value in when_notin:
            return False

        # Check for equality
        if when_eq is not None and (value is None or value != type(value)(when_eq)):
            return False
        if when_ne is not None and (value is None or value == type(value)(when_ne)):
            return False

        if when_lt is not None and (value is None or value >= type(value)(when_lt)):
            return False
        if when_lte is not None and (value is None or value > type(value)(when_lte)):
            return False
        if when_gt is not None and (value is None or value <= type(value)(when_gt)):
            return False
        if when_gte is not None and (value is None or value < type(value)(when_gte)):
            return False

        if when_startswith is not None \
                and (value is None or not value.startswith(when_startswith)):
            return False
        if when_notstartswith is not None \
                and (value is None or value.startswith(when_notstartswith)):
            return False
        if when_endswith is not None \
                and (value is None or not value.endswith(when_endswith)):
            return False
        if when_notendswith is not None \
                and (value is None or value.endswith(when_notendswith)):
            return False

    return True
