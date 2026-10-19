# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Dump python data to YAML.
"""

import io
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

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable=unused-argument
def __representer_none(self: Any, data: None) -> Any:
    return self.represent_scalar("tag:yaml.org,2002:null", "null")  # pragma: no cover


def __strip_yaml_version(string: str) -> str:
    tmp: list[str] = []
    for line in string.splitlines(True):
        if line.startswith("%YAML"):
            continue
        tmp.append(line)
    return "".join(tmp)


def ruyaml_dump_to_string(obj: Any, **kwargs: Any) -> str:
    """
    Dump a dict to a YAML-string.

        Parameters:
            obj (dict|[dict]): The dict to dump
            **kwargs (dict[str, Any]): Keyword arguments
                replace_empty (bool): True strips empty strings
                replace_empty_dict (bool): True strips empty dicts
                replace_null (bool): True strips null
    """
    replace_null: bool = deep_get(kwargs, DictPath("replace_null"), False)
    replace_empty: bool = deep_get(kwargs, DictPath("replace_empty"), False)
    replace_empty_dict: bool = deep_get(kwargs, DictPath("replace_empty_dict"), False)
    yaml_version: tuple[int, int] = deep_get(kwargs, DictPath("yaml_version"))
    ryaml.default_flow_style = deep_get(kwargs, DictPath("default_flow_style"), False)
    ryaml.representer.add_representer(type(None), __representer_none)
    f = io.StringIO()

    tmp_yaml_version = ryaml.version
    if yaml_version and yaml_version != (0, 0):
        ryaml.version = yaml_version
    if isinstance(obj, (dict, ruyaml.comments.CommentedMap, ruyaml.comments.CommentedSeq)):
        # Do not output a version prefix
        if yaml_version == (0, 0):
            ryaml.dump(obj, f, transform=__strip_yaml_version)
        else:
            ryaml.dump(obj, f)
    else:
        for d in obj:
            f.write("---\n")
            ryaml.dump(d, f)
    string = f.getvalue()
    f.close()
    if replace_empty:
        string = string.replace(r"''", "")
    if replace_empty_dict:
        string = string.replace(r"{}", "")
    if replace_null:
        string = string.replace(r"null", "")
    ryaml.version = tmp_yaml_version
    return string
