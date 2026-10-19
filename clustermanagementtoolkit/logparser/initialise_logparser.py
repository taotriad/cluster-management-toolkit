# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.logparser.init_parser_list import init_parser_list
from clustermanagementtoolkit.logparser.match_name import match_name
from clustermanagementtoolkit.logparser import logparser_types
from clustermanagementtoolkit.logparser.logparser_types import MatchRule
from clustermanagementtoolkit.logparser.logparser_types import Parser
from clustermanagementtoolkit.logparser.logparser_types import ParserRule


# pylint: disable-next=too-many-locals,too-many-branches
def initialise_logparser(**kwargs: Any) -> tuple[tuple[str | None, str | None], Parser | None]:
    """
    This (re-)initialises the parser; it will identify what parser rules to use
    helped by pod_name, container_name, and image_name;
    this allows for different containers in the same pod to use different parsers,
    and different versions of a pod to use different parsers.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                pod_name (str): The name of the pod
                container_name (str): The name of the container
                image_name (str): The name of the image
                override_parser (opaque): A reference to the parser rules
                                          to use instead of the autodetected parser
                container_type (str): Container or InitContainer
        Returns:
             ((str, str), Parser):
                ((str, str)):
                    (str): Subidentifiers to help explain
                           what rules in the parser file are used
                    (str): Name of the parser file used
                (Parser): A reference to the parser rules that are used
    """
    pod_name: str = deep_get(kwargs, DictPath("pod_name"), "raw")
    container_name: str = deep_get(kwargs, DictPath("container_name"), "")
    image_name: str = deep_get(kwargs, DictPath("image_name"), "")
    override_parser: Parser | None = deep_get(kwargs, DictPath("override_parser"))
    container_type: str = deep_get(kwargs, DictPath("container_type"), "Container")

    if not logparser_types.parsers:
        init_parser_list()

    if override_parser is not None:
        parser = None
        for parser in logparser_types.parsers:
            if parser.name == str(override_parser):
                return ("<override>", str(override_parser)), parser

    image_name = image_name.removeprefix("docker-pullable://")

    uparser: str | None = None
    lparser: str | None = None

    for parser in logparser_types.parsers:
        uparser = None
        lparser = None

        for matchrule_pod_name, matchrule_container_name, matchrule_image_prefix, \
                matchrule_container_type, matchrule_image_regex in parser.match:
            _image_name = image_name

            if matchrule_image_prefix.startswith("/"):
                tmp = image_name.split("/", 1)
                if len(tmp) == 2:
                    _image_name = f"/{tmp[1]}"

            # Will always match
            if not matchrule_image_prefix:
                matchrule_image_prefix = _image_name

            if matchrule_image_regex is None:
                regex_match = True
            else:
                tmp_match = matchrule_image_regex.search(_image_name)
                regex_match = tmp_match is not None

            if all((match_name(matchrule_pod_name, pod_name),
                    match_name(matchrule_container_name, container_name),
                    _image_name.startswith(matchrule_image_prefix),
                    container_type == matchrule_container_type, regex_match)):
                uparser = parser.name
                _lparser = []
                if matchrule_pod_name:
                    _lparser.append(matchrule_pod_name)
                if matchrule_container_name:
                    _lparser.append(matchrule_container_name)
                if matchrule_image_prefix:
                    _lparser.append(matchrule_image_prefix)
                lparser = "|".join(_lparser)
                break

        if lparser is not None:
            break

    if uparser is None and not lparser:
        lparser = "<unknown format>"
        uparser = "basic_8601"
        parser = Parser(name="basic_8601", show_in_selector=True,
                        match=[MatchRule("raw", "", "", "Container", None)],
                        rules=[ParserRule("ts_8601", {})])

    return (lparser, uparser), parser
