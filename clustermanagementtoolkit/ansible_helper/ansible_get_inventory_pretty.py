# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get the Ansible inventory and return it neatly formatted.
"""

from pathlib import Path
import re
import sys
from typing import Any

try:
    import ruyaml  # type: ignore[import-not-found,unused-ignore]
    ryaml = ruyaml.YAML()
    sryaml = ruyaml.YAML(typ="safe")
except ModuleNotFoundError:  # pragma: no cover
    try:
        import ruamel.yaml as ruyaml  # type: ignore[no-redef,unused-ignore]
        ryaml = ruyaml.YAML()
        sryaml = ruyaml.YAML(typ="safe")
    except ModuleNotFoundError:  # pragma: no cover
        sys.exit("ModuleNotFoundError: Could not import ruyaml/ruamel.yaml; "
                 "you may need to (re-)run `cmt-install.py` or `pip3 install ruyaml/ruamel.yaml`; "
                 "aborting.")

from clustermanagementtoolkit.cmtio_yaml import ruyaml_dump_to_string
from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtpaths import ANSIBLE_INVENTORY

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get, deep_pop, deep_set


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def ansible_get_inventory_pretty(**kwargs: Any) -> list[list[ANSIThemeStr] | str]:
    """
    Get the Ansible inventory and return it neatly formatted.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                groups ([str]): What groups to include
                highlight (bool): Apply syntax highlighting?
                include_groupvars (bool): Should group variables be included
                include_hostvars (bool): Should host variables be included
                include_hosts (bool): Should hosts be included
        Returns:
            ([str|[ANSIThemeStr]]): An unformatted list of strings
                                       or a formatted list of themearrays
    """
    groups: list[str] = deep_get(kwargs, DictPath("groups"), [])
    highlight: bool = deep_get(kwargs, DictPath("highlight"), False)
    include_groupvars: bool = deep_get(kwargs, DictPath("include_groupvars"), False)
    include_hostvars: bool = deep_get(kwargs, DictPath("include_hostvars"), False)
    include_hosts: bool = deep_get(kwargs, DictPath("include_hosts"), True)

    tmp: dict[str, Any] | ruyaml.comments.CommentedMap = {}

    if not Path(ANSIBLE_INVENTORY).is_file():
        return []

    try:
        d = dict(secure_read_yaml(ANSIBLE_INVENTORY))
    except TypeError:
        d = {}
    except ruyaml.constructor.DuplicateKeyError as e:
        if (re_tmp := re.match(r".*found duplicate key \"(.+?)\".*", str(e).replace("\n", "\\n"))):
            raise KeyError(f"duplicate key: {re_tmp[1]}") from e
        raise

    # We want the entire inventory
    if not groups:
        tmp = dict(d)
    else:
        if not (isinstance(groups, list) and groups and isinstance(groups[0], str)):
            raise TypeError(f"groups is type: {type(groups)}, expected {list}")
        for group in groups:
            if (item := deep_get(d, DictPath(group))) is not None:
                tmp[group] = item

    # OK, now we have a dict with only the groups we are interested in;
    # time for further post-processing.

    # do we want groupvars?
    if not include_groupvars:
        for group in tmp:
            deep_pop(tmp, DictPath(group), DictPath("vars"), None)
    else:
        for group in tmp:
            if not deep_get(tmp, DictPath(f"{group}#vars"), {}):
                deep_pop(tmp, DictPath(group), DictPath("vars"), None)

    # Do we want hosts?
    if not include_hosts:
        for group in tmp:
            deep_pop(tmp, DictPath(group), DictPath("hosts"), None)
    else:
        for group in tmp:
            if not deep_get(tmp, DictPath(f"{group}#hosts"), {}):
                deep_pop(tmp, DictPath(group), DictPath("hosts"), None)

        # OK, but do we want hostvars?
        if not include_hostvars:
            for group in tmp:
                for host in deep_get(tmp, DictPath(f"{group}#hosts"), {}):
                    deep_set(tmp, DictPath(f"{group}#hosts#{host}"), None)

    tmp_dump = ruyaml_dump_to_string(tmp, replace_null=True, replace_empty=True,
                                     replace_empty_dict=True)
    dump: list[list[ANSIThemeStr] | str] = []

    if highlight and tmp_dump:
        list_regex = re.compile(r"^(\s*)((- )+)(.*)")
        key_value_regex = re.compile(r"^(.*?)(:)(.*)")
        for data in tmp_dump.splitlines():
            # Is it a list?
            if (re_tmp := list_regex.match(data)) is not None:
                indent = re_tmp[1]
                listmarker = re_tmp[2]
                item = re_tmp[4]
                dump.append([ANSIThemeStr(indent, "default"),
                             ANSIThemeStr(listmarker, "yaml_list"),
                             ANSIThemeStr(item, "yaml_value")])
                continue

            # Is it key: value?
            if (re_tmp := key_value_regex.match(data)) is not None:
                key = re_tmp[1]
                separator = re_tmp[2]
                value = re_tmp[3]
                dump.append([ANSIThemeStr(key, "yaml_key"),
                             ANSIThemeStr(separator, "yaml_key_separator"),
                             ANSIThemeStr(value, "yaml_value")])
                continue

            # Nope, then we will use default format
            dump.append([ANSIThemeStr(data, "default")])
    else:
        dump = list(tmp_dump.splitlines())

    return dump
