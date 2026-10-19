# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any, cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit import formatters
from clustermanagementtoolkit.formatters import formatter_allowlist

from clustermanagementtoolkit import listgetters


def logpad_files(obj: dict, **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    A wrapper around listgetter_files() to use it as an infogetter.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments
                _pass_obj (bool): Should the object be passed to listgetter_files()?
                _show_raw (bool): Return unformatted entries?
                _extra_data#formatter (str): The formatter to use on the data
                _extra_data#formatter_args (dict): Arguments to pass to the formatter
                extra_values_lookup (dict): name/path to extra values to populate kwargs with
                                            from the object before passing it to listgetter_files()
    """
    # This is essentially just a wrapper around listgetter_files
    show_raw: bool = deep_get(kwargs, DictPath("_show_raw"), False)
    extra_values_lookup = deep_get(kwargs, DictPath("extra_values_lookup"), {})
    if (formatter := deep_get(obj, DictPath("_extra_data#formatter"))) is None:
        formatter = deep_get(kwargs, DictPath("formatter"), "none")
    formatter = deep_get(formatter_allowlist, DictPath(formatter), formatters.format_none)

    for key, path in extra_values_lookup.items():
        if "extra_values" not in kwargs:
            kwargs["extra_values"] = {}
        kwargs["extra_values"][key] = deep_get_with_fallback(obj, path, "")
    if "_pass_obj" in kwargs:
        kwargs["_obj"] = obj

    kwargs.pop("extra_values_lookup", "")

    vlist, status = listgetters.listgetter_files(**kwargs)

    if status != "OK":
        return []

    if (formatter_args := deep_get(obj, DictPath("_extra_data#formatter_args"))) is None:
        formatter_args = deep_get(kwargs, DictPath("formatter_args"), {})

    if "raw" not in formatter_args:
        formatter_args["raw"] = show_raw

    tmp = cast(str, vlist[0])

    if not show_raw and formatter.__name__ == formatters.render_markdown.__name__:
        if isinstance(vlist[0], list):
            tmp = "\n".join(vlist[0])
        else:
            tmp = str(vlist[0])
    return formatter(tmp, **formatter_args)
