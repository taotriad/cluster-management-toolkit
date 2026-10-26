# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A multi-purpose helper for generic_infogetter().
"""

from datetime import timedelta
import re
import sys
from typing import Any

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import age_to_seconds
from clustermanagementtoolkit.cmtlib import make_cel_expression
from clustermanagementtoolkit.cmtlib import make_label_selector
from clustermanagementtoolkit.cmtlib import make_set_expression
from clustermanagementtoolkit.cmtlib import make_set_expression_list
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_list
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.fieldgetters import fieldgetter_allowlist

from clustermanagementtoolkit.datagetters import datagetter_allowlist

from clustermanagementtoolkit.infogetters.__process_string import __process_string
from clustermanagementtoolkit.infogetters.process_value import process_value
from clustermanagementtoolkit.infogetters.transform_filter import transform_filter
from clustermanagementtoolkit.infogetters.transform_list import transform_list
from clustermanagementtoolkit.infogetters.when_filter import when_filter


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_obj(obj: dict, field_dict: dict, field_names: list[str],
            field_index: str, view: str, **kwargs: Any) -> dict | None:
    """
    Extract data for all fields in a list row from an object.

        Parameters:
            obj (dict): The object to extract data from
            field_dict (dict): The dict containing the description of the field
            field_names ([str]): The names of the fields to populate
            field_index (str): The index for the field list
            view (str): The name of the view
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                filters (dict): The filters to apply
                deleted (bool): Is the entry deleted?
                caller_obj (dict): Used for lookups when doing path substitutions
        Returns:
            (dict): A dict with the data for all fields in the field_names list
    """
    kh = deep_get(kwargs, DictPath("kubernetes_helper"))
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    d = {}

    filters: dict[str, Any] = deep_get(kwargs, DictPath("filters"), {})
    deleted: bool = deep_get(kwargs, DictPath("deleted"), False)
    caller_obj: dict = deep_get(kwargs, DictPath("caller_obj"), {})
    duration: int = -1

    # fields both specify formatting and where to get the data from;
    # here we are only concerned with the data
    # pylint: disable-next=too-many-nested-blocks
    for field_name in field_names:
        name = field_name
        field = field_dict[name]
        path = deep_get(field, DictPath("path"))
        paths = deep_get(field, DictPath("paths"), [])
        path_substitutions = deep_get(field, DictPath("path_substitutions"), {})
        unique_values = deep_get(field, DictPath("unique"), False)
        if caller_obj and path_substitutions:
            substitutions = {}
            for subst, subst_with in path_substitutions.items():
                if isinstance(subst_with, list):
                    subst_with = deep_get_with_fallback(caller_obj, subst_with)
                substitutions[subst] = subst_with
            path = cmtlib.substitute_string(path, substitutions)
        datagetter = deep_get(field, DictPath("datagetter"))
        if isinstance(datagetter, str):
            datagetter = deep_get(datagetter_allowlist, DictPath(datagetter))
        if "default" not in field:
            default = ""
        else:
            default = deep_get(field, DictPath("default"))
        global_default: Any = default
        fallback_on_empty = deep_get(field, DictPath("fallback_on_empty"), False)
        formatter = deep_get(field, DictPath("formatter"))
        action = None
        newlines = None
        replace_quotes = None

        if (path is None and not paths or path is not None and paths) and datagetter is None:
            raise ValueError(f"Field {name}: exactly one of path and paths must be non-empty "
                             f"unless a datagetter is specified\npath={path}\n"
                             f"paths={paths}\ndatagetter={datagetter}")

        if datagetter is not None:
            d[name], extradata = datagetter(obj, kubernetes_helper=kh, path=path, default=default)
            for key, value in extradata.items():
                d[key] = value
        else:
            _values = []

            if path is not None:
                if deep_get(field, DictPath("type")) is None:
                    raise ValueError(f"Field {name}: the path field has no default type; "
                                     "type must always be specified")
                tmp_value = deep_get(obj, DictPath(path), global_default)
                if isinstance(tmp_value, (str, list)) \
                        and not tmp_value and fallback_on_empty:
                    tmp_value = global_default
                _values.append((tmp_value, deep_get(field, DictPath("type"))))

            _path = None
            for _path in paths:
                default = deep_get(_path, DictPath("default"))
                vtype = deep_get(_path, DictPath("type"), "raw")
                path = deep_get(_path, DictPath("path"))
                mpaths = deep_get(_path, DictPath("paths"))
                if path is not None and mpaths is not None or path is None and mpaths is None:
                    raise ValueError(f"Field {name}: exactly one of path & paths must be used "
                                     f"in a 'paths:' block\npath={path}\npaths={paths}")

                if mpaths is None:
                    if isinstance(path, str):
                        path = [path]
                    mpaths = [path]

                ptype = deep_get(_path, DictPath("pathtype"), "list")
                limit = deep_get(_path, DictPath("limit"))
                action = deep_get(_path, DictPath("action"), "")
                subpath = deep_get(_path, DictPath("subpath"), "")
                subpaths = deep_get(_path, DictPath("subpaths"), [])
                fallback_on_empty = deep_get(_path, DictPath("fallback_on_empty"), False)
                replace_quotes = deep_get(_path, DictPath("replace_quotes"), "keep")
                newlines = deep_get(_path, DictPath("newlines"), "escape")
                if ptype == "list":
                    tmp = deep_get_with_fallback(obj, path, default=default,
                                                 fallback_on_empty=fallback_on_empty)
                    if deep_get(_path, DictPath("sorted"), False) and tmp is not None:
                        tmp = natsorted(tmp)

                    if tmp is not None and tmp in ("None", ["None"]) \
                            and deep_get(_path, DictPath("none_str_as_none"), False):
                        tmp = default

                    # Just return the list, unless a subset has been requested
                    if limit is not None and tmp is not None:
                        value = tmp[0:limit]
                    else:
                        value = tmp

                    _values.append((value, vtype))
                elif ptype == "dictlist":
                    _raw = deep_get_with_fallback(obj, path, default=default,
                                                  fallback_on_empty=fallback_on_empty)
                    transform = deep_get(_path, DictPath("transform"), {})
                    if _raw is not None:
                        for tmp in transform_list(_raw, transform=transform):
                            _values.append((tmp, vtype))
                # This takes a list of paths as indata, and--for all numerical entries in the list,
                # builds ranges; all non-numerical entries are included as is
                elif ptype == "ranges":
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
                        for i, sortedval in enumerate(sortedvals):
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
                    _values.append((rangevals, "raw"))
                elif ptype == "identify_type":
                    tmp = deep_get_with_fallback(obj, path, {})
                    vtype, _value = cmtlib.decode_value(tmp)
                    _values.append((vtype, "str"))
                elif ptype == "constant":
                    # The constant is taken from the default value.
                    _values.append((default, "raw"))
                elif ptype == "obj":
                    reparent = deep_get(_path, DictPath("reparent"))
                    if not path:
                        tmp = obj
                    else:
                        tmp = deep_get_with_fallback(obj, path, {})
                    if reparent:
                        if tmp:
                            _values.append(([{reparent: tmp}], "raw"))
                        else:
                            _values.append((default, "raw"))
                    else:
                        if not tmp and default:
                            tmp = default
                        _values.append(([tmp], "raw"))
                elif ptype == "key_value":
                    value = []
                    tmp = deep_get_with_fallback(obj, path, {})
                    subtype = deep_get(_path, DictPath("subtype"), "dict")
                    # This is to be for key_value-lists provided as strings
                    if subtype == "strlist" and isinstance(tmp, str):
                        strlist = {}
                        for kv in tmp.split(","):
                            kv_tuple = kv.split("=")
                            if len(kv_tuple) != 2:
                                break
                            strlist[kv_tuple[0]] = kv_tuple[1]
                            tmp = strlist
                    if isinstance(tmp, list):
                        tmp2: dict[str, Any] = {}
                        for item in tmp:
                            if not isinstance(item, dict):
                                break
                            tmp2 = {**tmp2, **item}
                        tmp = tmp2
                    for _key, _value in tmp.items():
                        subpaths = deep_get(_path, DictPath("subpaths"), [])
                        if subpaths:
                            _value = deep_get_with_fallback(_value, subpaths)
                        if not when_filter(_path, item={}, key=_key, value=_value):
                            continue
                        _regexes_key = deep_get(_path, DictPath("key#regex"), [])
                        _regexes_value = deep_get(_path, DictPath("value#regex"), [])
                        if isinstance(_regexes_key, str):
                            _regexes_key = [_regexes_key]
                        if isinstance(_regexes_value, str):
                            _regexes_value = [_regexes_value]
                        _key = transform_filter(_key,
                                                deep_get(_path, DictPath("key#transform"), {}))
                        _value = transform_filter(_value,
                                                  deep_get(_path, DictPath("value#transform"), {}))
                        # A regex for key/value is required to capture only one group;
                        # (though conceivably there might be scenario for joining),
                        # thus the first non-None capture group will exit the match;
                        # when using multiple regexes the first matching regex exits
                        match = False
                        for _regex in _regexes_key:
                            if (re_tmp := re.match(_regex, _key)) is None:
                                continue

                            for group in re_tmp.groups():
                                if group is not None:
                                    _key = group
                                    match = True
                            if match:
                                break
                        match = False
                        for _regex in _regexes_value:
                            if (re_tmp := re.match(_regex, _value)) is None:
                                continue

                            for group in re_tmp.groups():
                                if group is not None:
                                    _value = group
                                    match = True
                            if match:
                                break
                        # A transform might yield multiple identical key/value pairs;
                        # ignore all except the first one
                        if (_key, _value) in value:
                            continue
                        value.append((_key, _value))
                    if not value:
                        if default is None:
                            value = []
                        else:
                            value = default
                    for tmp in value:
                        _values.append((tmp, vtype))
                elif ptype == "selectors":
                    value = []
                    # This is a list of selectors
                    # pylint: disable-next=too-many-boolean-expressions
                    if not path and isinstance(obj, dict) and ("matchExpressions" in obj
                                                               or "matchFields" in obj
                                                               or "matchLabels" in obj
                                                               or "cel" in obj):
                        tmp = [obj]
                    else:
                        tmp = deep_get_with_fallback(obj, path, [])
                    if isinstance(tmp, dict):
                        tmp = [tmp]
                    for selector in tmp:
                        if "matchExpressions" in selector:
                            value.append(make_set_expression(selector["matchExpressions"]))
                        if "matchFields" in selector:
                            value.append(make_set_expression(selector["matchFields"]))
                        if "matchLabels" in selector:
                            value.append(make_label_selector(selector["matchLabels"]))
                        if "cel" in selector:
                            value.append(make_cel_expression([selector["cel"]]))
                    if not value and default:
                        _values.append((default, "raw"))
                    elif len(value) == 1:
                        _values.append((value[0], "str"))
                    else:
                        _values.append((",".join(value), "str"))
                elif ptype in ("match_expression", "toleration"):
                    tmp = deep_get_with_fallback(obj, path)
                    if isinstance(tmp, list):
                        value = []
                        value = make_set_expression_list(tmp, is_toleration=ptype == "toleration")
                        if len(value) == 1:
                            _values.append((value[0], "raw"))
                        else:
                            for tmp in value:
                                _values.append((tmp, "raw"))
                    elif isinstance(tmp, dict):
                        # XXX: Is this code really used?
                        value = make_set_expression_list([tmp], is_toleration=ptype == "toleration")
                        _values.append((value, "raw"))
                    else:
                        _values.append((default, "raw"))
                elif ptype == "lookup":
                    vtype = deep_get(_path, DictPath("type"), "raw")
                    tmp_lookup_selector = []
                    tmp_lookup_field_selector = []
                    if len(path) == 5:
                        lookup_kind, lookup_api_group, lookup_namespace, \
                            lookup_name, tmp_lookup_selector = path
                    elif len(path) == 6:
                        lookup_kind, lookup_api_group, lookup_namespace, \
                            lookup_name, tmp_lookup_selector, tmp_lookup_field_selector = path
                    if isinstance(lookup_kind, list):
                        lookup_kind = deep_get_with_fallback(obj, lookup_kind, "")
                    if isinstance(lookup_api_group, list):
                        lookup_api_group = deep_get_with_fallback(obj, lookup_api_group, "")
                    if isinstance(lookup_namespace, list):
                        lookup_namespace = deep_get_with_fallback(obj, lookup_namespace, "")
                    if isinstance(lookup_name, list):
                        lookup_name = deep_get_with_fallback(obj, lookup_name, "")
                    if not tmp_lookup_selector:
                        lookup_selector = ""
                    else:
                        _lookup_selector = {}
                        for ls in tmp_lookup_selector:
                            ls_key = ls[0]
                            ls_value = ls[1]
                            if isinstance(ls_value, list):
                                ls_value = deep_get_with_fallback(obj, ls_value)
                            _lookup_selector[ls_key] = ls_value
                        lookup_selector = make_label_selector(_lookup_selector)
                    if not tmp_lookup_field_selector:
                        lookup_field_selector = ""
                    else:
                        _lookup_selector = {}
                        for ls in tmp_lookup_field_selector:
                            ls_key = ls[0]
                            ls_value = ls[1]
                            if isinstance(ls_value, list):
                                ls_value = deep_get_with_fallback(obj, ls_value)
                            _lookup_selector[ls_key] = ls_value
                        lookup_field_selector = make_label_selector(_lookup_selector)

                    try:
                        if not lookup_name:
                            lookup_obj, _status = \
                                kh.get_list_by_kind_namespace((lookup_kind, lookup_api_group),
                                                              lookup_namespace,
                                                              label_selector=lookup_selector,
                                                              field_selector=lookup_field_selector,
                                                              resource_cache=kh_cache)
                        else:
                            lookup_obj = \
                                kh.get_ref_by_kind_name_namespace((lookup_kind, lookup_api_group),
                                                                  lookup_name, lookup_namespace,
                                                                  resource_cache=kh_cache)
                    except NameError:
                        unknown = deep_get(_path, DictPath("unknown"), "Unknown Kind")
                        _values.append((unknown, "raw"))
                        continue
                    if lookup_obj is None \
                            or isinstance(lookup_obj, dict) and not when_filter(_path,
                                                                                item=lookup_obj):
                        _values.append((default, "raw"))
                        continue
                    subpaths = deep_get(_path, DictPath("subpaths"), [])
                    value = []
                    if subpaths:
                        tmp = []
                        if isinstance(lookup_obj, dict):
                            lookup_obj = [lookup_obj]

                        for _lookup_obj in lookup_obj:
                            for i, subpath in enumerate(subpaths):
                                tmp.append(deep_get(_lookup_obj, DictPath(subpath)))
                        if len(tmp) == 1:
                            value.append(tmp[0])
                        else:
                            value.append(tuple(tmp))

                    if not value:
                        value = default

                    substitute = deep_get(_path, DictPath("substitute"))
                    if substitute is not None:
                        value = substitute
                    if vtype == "len" and value:
                        if len(value) > 1:
                            value = len(value)
                        elif isinstance(value, list) and isinstance(value[0], tuple):
                            value = len(value[0])
                    _values.append((value, "raw"))
                elif ptype == "remap":
                    value = []
                    substitutions = deep_get(_path, DictPath("substitutions"), "")
                    tmp = deep_get_with_fallback(obj, path)
                    if tmp is None:
                        tmp = []

                    if type(tmp) in (bool, int, str):
                        tmp = [tmp]

                    if isinstance(tmp, list):
                        for _tmp in tmp:
                            if isinstance(_tmp, bool):
                                _tmp = f"__{_tmp!s}"

                            if _tmp in substitutions:
                                value.append(substitutions.get(_tmp))
                            elif "__default" in substitutions:
                                value.append(substitutions.get("__default"))
                            else:
                                value.append(_tmp)
                    else:
                        raise ValueError(f"remap is not supported yet for type {type(tmp)}")
                    if not value:
                        if default is None:
                            continue
                        value.append(default)
                    for tmp in value:
                        _values.append((tmp, vtype))
                elif ptype == "substitution":
                    value = []
                    substitute = deep_get(_path, DictPath("substitute"), "")
                    tmp = deep_get_with_fallback(obj, path)
                    if tmp is None:
                        tmp = []
                    if not isinstance(tmp, list):
                        tmp = [tmp]
                    for _tmp in tmp:
                        if not when_filter(_path, item=_tmp):
                            continue
                        value.append(substitute)
                        break
                    else:
                        if "else" in _path:
                            tmp = deep_get(_path, DictPath("else"))
                            if isinstance(tmp, list):
                                tmp = deep_get_with_fallback(obj, tmp)
                            if tmp:
                                value.append(tmp)
                    if not value:
                        if default is None:
                            continue
                        value.append(default)
                    for tmp in value:
                        _values.append((tmp, vtype))
                elif ptype == "transform":
                    transform = deep_get(_path, DictPath("transform"), {})
                    tmp = deep_get_with_fallback(obj, path)
                    tmp_type = type(tmp)
                    if not isinstance(tmp, (dict, list)):
                        tmp = [tmp]
                    tmp = transform_list(tmp, transform)
                    if tmp_type not in (dict, list) and len(tmp) == 1:
                        tmp = tmp[0]
                    _values.append((tmp, vtype))
                elif ptype == "milliseconds":
                    tmp = deep_get_with_fallback(obj, path, 0)
                    duration = age_to_seconds(f"{tmp}ms")
                    # Default to 1 second, since 0 == <unset>
                    if not duration:
                        duration = 1
                    _values.append((duration, "age"))
                elif ptype == "timediff":
                    if len(mpaths) != 2:
                        raise ValueError(f"Field {name}: when using pathtype: 'timediff' "
                                         "path must be [start_time_path(s), end_time_path(s)]")
                    start_time = deep_get_with_fallback(obj, mpaths[0], default=None)
                    end_time = deep_get_with_fallback(obj, mpaths[1], default=None)
                    if end_time is None or start_time is None:
                        duration = -1
                    else:
                        datetime_start = timestamp_to_datetime(start_time)
                        if isinstance(end_time, int):
                            datetime_end = datetime_start + timedelta(seconds=end_time)
                        else:
                            datetime_end = timestamp_to_datetime(end_time)
                        timediff = datetime_end - datetime_start
                        duration = int(timediff.total_seconds())
                        _values.append((duration, "raw"))
                elif ptype == "comparison":
                    # Input is two paths; output is the value of the first path
                    # and -2/-1/0/1 (for type mismatch, lt, eq, gt)
                    if isinstance(default, list) and len(default) == 2:
                        _default1, _default2 = default
                    else:
                        _default1 = _default2 = default
                    if len(path) == 1:
                        tmp_val = deep_get_with_fallback(obj, path, default)
                        try:
                            val1, val2 = tmp_val.split("/")
                        except ValueError:
                            val1, val2 = default
                    else:
                        val1 = deep_get(obj, DictPath(path[0]), _default1)
                        val2 = deep_get(obj, DictPath(path[1]), _default2)
                    if type(val1) != type(val2):  # noqa: E721
                        res = -2
                    elif val1 == val2:
                        res = 0
                    elif val1 < val2:
                        res = -1
                    else:
                        res = 1
                    _values.append(((val1, res), "raw"))
                elif ptype == "timestamp_with_age":
                    # The first array is assumed to be the start time, the second array the end time
                    start_time = None
                    end_time = None
                    start_time_index = -1
                    end_time_index = -1
                    for i, mpath in enumerate(mpaths):
                        if isinstance(mpath, list):
                            if start_time_index == -1:
                                start_time_index = i
                                start_time = deep_get_with_fallback(obj, mpath, default=None)
                            elif end_time_index == -1:
                                end_time_index = i
                                end_time = deep_get_with_fallback(obj, mpath, default=None)
                            else:
                                raise ValueError(f"{field_name} received too many timestamp paths; "
                                                 "the view file is most likely malformed")
                    if end_time is None or start_time is None:
                        end_time = None
                        duration = -1
                    else:
                        timediff = \
                            timestamp_to_datetime(end_time) - timestamp_to_datetime(start_time)
                        if (duration := timediff.days * 24 * 60 * 60 + timediff.seconds) == 0:
                            duration = 1
                        # If the task completes so quickly that start_time == end_time
                        # duration will end up as 0. The result of this would be that
                        # it's represented as <unset>.
                        # To work around this we set duration to 1 if duration == 0.
                    __values = []
                    for i, mpath in enumerate(mpaths):
                        if i == start_time_index:
                            __values.append(end_time)
                        elif i == end_time_index:
                            __values.append(duration)
                        else:
                            __values.append(mpath)
                    _values.append((tuple(__values), "raw"))
                elif ptype == "fieldgetter":
                    fieldgetter_data = deep_get_with_fallback(obj, path, {})
                    if not fieldgetter_data:
                        continue
                    fieldgetter_tmp = deep_get(fieldgetter_data, DictPath("fieldgetter"))
                    fieldgetter = deep_get(fieldgetter_allowlist, DictPath(fieldgetter_tmp))
                    if fieldgetter is None:
                        raise ValueError(f"{fieldgetter_tmp} is not a valid fieldgetter; "
                                         "the view-file is probably incorrect.")
                    fieldgetter_args = deep_get(fieldgetter_data, DictPath("fieldgetter_args"), {})
                    tmp = fieldgetter(**fieldgetter_args, kubernetes_helper=kh)
                    _values.append((tmp, vtype))
                elif ptype in ("items", "appenditems"):
                    if subpath:
                        if subpaths:
                            raise ValueError(f"Field {name}: when using action: 'items' exactly "
                                             "one of subpath and subpaths must be specified")
                        subpaths = [subpath]
                    value = []
                    items = []
                    index = deep_get(_path, DictPath("index"))
                    for mpath in mpaths:
                        if isinstance(mpath, str):
                            mpath = [mpath]
                        tmp = deep_get_list(obj, mpath, default=[],
                                            fallback_on_empty=fallback_on_empty)
                        if tmp is not None and index is not None:
                            try:
                                tmp = [tmp[index]]
                            except IndexError:
                                pass
                        # XXX: This is to avoid breaking anything
                        # Ideally the "appenditems" behaviour should be the only one,
                        # but requires rewriting a lot of files
                        if ptype == "items":
                            items += tmp
                        else:
                            items.append(tmp)
                    for item in items:
                        if not when_filter(_path, item):
                            continue

                        tmp = []
                        for i, subpath in enumerate(subpaths):
                            if isinstance(default, list):
                                if i < len(default):
                                    _default = default[i]
                                else:
                                    _default = None
                            else:
                                _default = default

                            if (vtype in ("int", "float") or action in ["sum"]) \
                                    and type(default) not in (int, float):
                                _default = 0

                            if isinstance(subpath, dict):
                                _subpath = deep_get(subpath, DictPath("str"))
                                if _subpath is not None:
                                    tmp.append(_subpath)
                                else:
                                    _subpath = deep_get(subpath, DictPath("subpath"))
                                    _default = deep_get(subpath, DictPath("default"), _default)
                                    _fallback_path = deep_get(subpath, DictPath("fallback_path"))
                                    _fallback_value = deep_get(obj, DictPath(_fallback_path))
                                    if _fallback_value is not None and _default is None:
                                        _default = _fallback_value
                                    if isinstance(_subpath, str):
                                        _subpath = [_subpath]
                                    _regexes = deep_get(subpath, DictPath("regex"), [])
                                    if isinstance(_regexes, str):
                                        _regexes = [_regexes]
                                    _raw = deep_get_with_fallback(item, _subpath, _default)
                                    _raw = transform_filter(_raw,
                                                            deep_get(subpath,
                                                                     DictPath("transform"), {}))
                                    for _regex in _regexes:
                                        if (re_tmp := re.match(_regex, _raw)) is not None:
                                            for group in re_tmp.groups():
                                                if group is not None:
                                                    tmp.append(group)
                                            break
                                        tmp.append("")
                                    if not tmp or not _regexes:
                                        tmp.append(_raw)
                            else:
                                prefix = deep_get(_path, DictPath("prefix"), [])
                                suffix = deep_get(_path, DictPath("suffix"), [])
                                regex_ = deep_get(_path, DictPath("regex"))
                                _subpath = subpath
                                if isinstance(_subpath, str):
                                    _subpath = [_subpath]
                                tmp_ = deep_get_with_fallback(item, _subpath, _default)
                                if isinstance(tmp_, str):
                                    if regex_:
                                        if (re_tmp := re.match(regex_, tmp_)) is not None:
                                            tmp_ = []
                                            for group in re_tmp.groups():
                                                if group is not None:
                                                    tmp_.append(group)
                                            if len(tmp_) > 1:
                                                tmp_ = tuple(_tmp)
                                        elif fallback_on_empty:
                                            tmp_ = _default
                                    else:
                                        tmp_ = __process_string(tmp_, quotes="same")
                                if isinstance(prefix, str):
                                    if isinstance(tmp_, str):
                                        tmp_ = prefix + tmp_
                                    else:
                                        tmp_ = [prefix] + tmp_
                                else:
                                    tmp += prefix

                                if isinstance(suffix, str):
                                    if isinstance(tmp_, str):
                                        tmp_ += suffix
                                    else:
                                        tmp_ += [suffix]

                                tmp.append(tmp_)

                                if isinstance(suffix, list):
                                    tmp += suffix
                        if not limit or len(value) < limit:
                            if len(tmp) == 1:
                                value.append(tmp[0])
                            else:
                                value.append(tuple(tmp))
                    if not value:
                        value = default
                    if value is not None:
                        if action in ("sum", "latest", "earliest"):
                            _values.append((value, vtype))
                        else:
                            for tmp in value:
                                _values.append((tmp, vtype))
                elif ptype == "count":
                    count = 0
                    for p in path:
                        count += len(deep_get(obj, DictPath(p), {}))
                    _values.append((count, vtype))
                elif ptype == "split":
                    value = []
                    separator = deep_get(_path, DictPath("separator"), ",")
                    _raw = deep_get_with_fallback(obj, path, "")
                    if _raw is not None:
                        for tmp in _raw.split(separator):
                            _values.append((tmp, vtype))
                elif ptype == "regex":
                    value = []
                    _raw = deep_get_with_fallback(obj, path, "")
                    _regexes = deep_get(_path, DictPath("regex"), [])
                    if isinstance(_regexes, str):
                        _regexes = [_regexes]
                    if _raw is not None and _raw:
                        for _regex in _regexes:
                            if (re_tmp := re.match(_regex, _raw)) is not None:
                                for group in re_tmp.groups():
                                    if group is not None:
                                        value.append(group)
                                break
                    elif default:
                        value = default
                    value = tuple(value)
                    _values.append((value, "raw"))
                elif ptype == "tuple":
                    value = []
                    if not when_filter(_path, item=obj):
                        continue
                    for i, element in enumerate(path):
                        if isinstance(default, list):
                            if i < len(default):
                                _default = default[i]
                            else:
                                _default = None
                        else:
                            _default = default

                        if vtype in ("int", "float") and type(default) not in (int, float):
                            _default = 0

                        # This is a literal string, not a path
                        if isinstance(element, str):
                            tmp = element
                        else:
                            tmp = deep_get_with_fallback(obj, element, default=_default,
                                                         fallback_on_empty=fallback_on_empty)

                        if vtype == "api_group":
                            override_paths = [DictPath(f"Views#{view}#kind_format_{field_index}"),
                                              DictPath(f"Views#{view}#kind_format"),
                                              DictPath(f"Global#kind_format_{field_index}"),
                                              DictPath("Global#kind_format")]
                            override_kind = \
                                deep_get_with_fallback(cmtlib.cmtconfig, override_paths, "mixed")
                            if override_kind == "skip" \
                                    or override_kind == "mixed" and "." not in tmp:
                                tmp = ""
                            vtype = "kind"
                        value.append(tmp)
                    if isinstance(deep_get(_path, DictPath("substitute")), list):
                        value = deep_get(_path, DictPath("substitute"))
                    value = tuple(value)
                    _values.append((value, vtype))
                elif ptype == "status_tuple":
                    if "lookup" in _path:
                        lookup_kind = deep_get(_path, DictPath("lookup#kind"))
                        lookup_api_family = deep_get(_path, DictPath("lookup#api_family"))
                        lookup_status = deep_get(_path, DictPath("lookup#status"))
                    else:
                        raise ValueError(f"Field {name}: currently status_tuple "
                                         "only supports 'lookup'")
                    path = deep_get(_path, DictPath("path"))
                    value = deep_get(obj, DictPath(path))
                    tmp = kh.get_ref_by_kind_name_namespace((lookup_kind, lookup_api_family),
                                                            value, "", resource_cache=kh_cache)
                    if lookup_status == "highlight":
                        if tmp is None:
                            status_group = StatusGroup.NOT_OK
                        else:
                            status_group = StatusGroup.OK
                        value = (value, status_group)
                    elif lookup_status == "message":
                        if tmp is None:
                            value = (deep_get(_path, DictPath("lookup#messages#not_ok")),
                                     StatusGroup.NEUTRAL)
                        else:
                            value = (deep_get(_path, DictPath("lookup#messages#ok")),
                                     StatusGroup.NEUTRAL)
                    _values.append((value, "raw"))
                elif ptype == "dictkeys":
                    for mpath in mpaths:
                        tmp = list(deep_get_with_fallback(obj, mpath, {}))
                        if tmp:
                            _values.append((tmp, "raw"))
                elif ptype == "dictfields":
                    subpaths = deep_get_with_fallback(_path, [DictPath("subpaths"),
                                                              DictPath("subpath")], [])
                    if isinstance(subpaths, str):
                        subpaths = [[subpaths]]
                    for mpath in mpaths:
                        tmp = deep_get_with_fallback(obj, mpath)
                        if not when_filter(_path, item=tmp):
                            continue
                        value = []
                        for key in subpaths:
                            if isinstance(key, str):
                                value.append(key)
                            else:
                                value.append(deep_get_with_fallback(tmp, key, default))
                        if len(value) == 1:
                            _values.append((value[0], "raw"))
                        else:
                            _values.append((tuple(value), "raw"))
                else:
                    value = deep_get_with_fallback(obj, path, default,
                                                   fallback_on_empty=fallback_on_empty)
                    if value is not None:
                        _values.append((value, vtype))
            values = []

            processor_args = {
                "action": action,
                "field_index": field_index,
                "field_name": name,
                "formatter": formatter,
                "newlines": newlines,
                "regex_": deep_get(_path, DictPath("regex")),
                "replace_quotes": replace_quotes,
                "view": view,
            }
            if unique_values:
                # Remove duplicates
                _values = list(dict.fromkeys(_values))
            for value, vtype_ in _values:
                if isinstance(vtype_, list) and not value:
                    value = []
                if isinstance(value, list) and vtype_ == "raw":
                    values += value
                    continue
                if isinstance(value, list) and isinstance(vtype_, list):
                    tmp = []
                    for value_ in value:
                        tmp.append(process_value(value_, vtype_, **processor_args))
                else:
                    tmp = process_value(value, vtype_, **processor_args)
                values.append(tmp)

            if not values:
                values = global_default

            if isinstance(values, list) and len(values) == 1 and formatter != "list":
                d[name] = values[0]
            else:
                d[name] = values

    # We've got all the information we can get now; time to apply filters
    skip = False
    for f_filter in filters.values():
        if not deep_get(f_filter, DictPath("enabled"), True):
            continue

        # If len(allow) > 0, we only allow fields that match
        allow = deep_get(f_filter, DictPath("allow"), [])
        # If len(block) > 0, we skip fields that match
        block = deep_get(f_filter, DictPath("block"), [])
        source = deep_get(f_filter, DictPath("source"), "")
        if source == "object":
            src = obj
        else:
            src = d
        if allow:
            # If all field + value pairs match we allow
            for rule in allow:
                key = deep_get(rule, DictPath("key"), "")
                values = deep_get(rule, DictPath("values"), "")

                if deep_get(src, DictPath(key), "").rstrip() not in values:
                    skip = True
                    break
        if block:
            # If all field + value pairs match we block
            for rule in block:
                key = deep_get(rule, DictPath("key"), "")
                values = deep_get(rule, DictPath("values"), "")
                if deep_get(src, DictPath(key), "").rstrip() in values:
                    skip = True
                    break
        if skip:
            break
    if skip:
        entry = None
    else:
        d["ref"] = obj
        d["__deleted"] = deleted
        d["__uid"] = deep_get(obj, DictPath("metadata#uid"))
        entry = dict(d)

    return entry
