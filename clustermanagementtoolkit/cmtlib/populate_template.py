# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Inject data into a template.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_set


def populate_template(template: dict[str, Any], injections: dict[str, Any],
                      **kwargs: Any) -> dict[str, Any]:
    """
    Given a template, a list of injections to make into that template,
    and a set of data sources, inject data from those sources into the template,
    and return the populated template.

        Parameters:
            template (dict[str, Any]): A template to populate
            injections (dict[str, Any]): A dict that describes what injections to make:
                                         source_path:
                                           source: "source to get data from"
                                           paths: [
                                             "paths in template to populate with data",
                                           ],
        Returns:
            (dict[str, Any]): The populated template.
    """
    for src_path, data in injections.items():
        # source specifies where to get data from;
        # by default we get it from the object named obj.
        # query is reserved for variables obtained through user queries.
        source = deep_get(data, DictPath("source"), "obj")
        dst_paths = deep_get(data, DictPath("paths"), [])
        value = deep_get(kwargs, DictPath(f"{source}#{src_path}"), None)
        for dst_path in dst_paths:
            deep_set(template, DictPath(dst_path), value, create_path=True)
    return template
