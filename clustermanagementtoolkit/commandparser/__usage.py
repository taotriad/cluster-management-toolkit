# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Display usage information.
"""

import errno
import sys

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemearray_to_str
from clustermanagementtoolkit.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint import themearray_len
from clustermanagementtoolkit.ansithemeprint import themearray_ljust

from clustermanagementtoolkit.commandparser import commandparser_types

from clustermanagementtoolkit.cmtlib import lstrip_count
from clustermanagementtoolkit.cmtlib import rstrip_count

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=unused-argument,too-many-locals,too-many-branches,too-many-statements
def __usage(options: list[tuple[str, str]], args: list[str]) -> int:
    """
    Display usage information.

        Parameters:
            options ([(str, str)]): Options to use when executing this action
            args ([str]): [unused]
        Returns:
            (int): 0
    """
    has_commands: bool = False
    has_options: bool = False
    has_args: bool = False
    debug: bool = False

    output: list[list[ANSIThemeStr]] = []
    output_format: str = "default"

    for opt, optarg in options:
        if opt == "--debug":
            debug = True
        if opt == "--format":
            output_format = optarg

    maxlen = 0
    commands = []
    commandcount = 0
    globaloptioncount = 0

    # Do we have any arguments?
    for key, value in commandparser_types.commandline.items():
        required_args_ = deep_get(commandparser_types.commandline,
                                  DictPath(f"{key}#required_args"), [])
        optional_args_ = deep_get(commandparser_types.commandline,
                                  DictPath(f"{key}#optional_args"), [])
        if (required_args_ or optional_args_
                or deep_get(commandparser_types.commandline,
                            DictPath(f"{key}#max_args"), 0)) and key != "Help":
            has_args = True
            break

    # Do we have any options?
    for key, value in commandparser_types.commandline.items():
        if key in ("__default", "__*", "extended_description") or key.startswith("spacer"):
            continue

        if key.startswith("__"):
            globaloptioncount += 1
        else:
            commandcount += 1

        if deep_get(value, DictPath("options"), {}) and key not in ("Help", "Help2"):
            has_options = True

    # Do we have any commands?
    if commandcount > 3:
        has_commands = True

    if not has_commands:
        commandparser_types.commandline.pop("Help", None)

    if output_format in ("default", "short"):
        headerstring = [ANSIThemeStr(f"{commandparser_types.programname}", "programname")]
    elif output_format == "markdown":  # pragma: no branch
        headerstring = [ANSIThemeStr(f"# ___`{commandparser_types.programname}`___", "default")]
    else:
        headerstring = []

    if has_commands:
        if output_format == "default":
            headerstring += [ANSIThemeStr(" COMMAND", "command")]
        elif output_format == "markdown":  # pragma: no branch
            headerstring += [ANSIThemeStr(" __`COMMAND`__", "default")]

    if has_options and output_format != "short":
        if output_format == "default":
            headerstring += [ANSIThemeStr(" [", "separator"),
                             ANSIThemeStr("OPTION", "option"),
                             ANSIThemeStr("]", "separator"),
                             ANSIThemeStr("...", "option")]
        elif output_format == "markdown":  # pragma: no branch
            headerstring += [ANSIThemeStr(" _`[OPTION]`_...", "default")]
    if has_args:
        if output_format == "default":
            headerstring += [ANSIThemeStr(" [", "separator"),
                             ANSIThemeStr("ARGUMENT", "argument"),
                             ANSIThemeStr("]", "separator"),
                             ANSIThemeStr("...", "argument")]
        elif output_format == "markdown":  # pragma: no branch
            headerstring += [ANSIThemeStr(" _`[ARGUMENT]`_...", "default")]

    output.append(headerstring)
    output.append([ANSIThemeStr("", "default")])
    output.append([ANSIThemeStr(commandparser_types.programdescription, "description")])
    output.append([ANSIThemeStr("", "default")])

    if has_commands:
        if output_format in ("default", "short"):
            output.append([ANSIThemeStr("Commands:", "description")])
        elif output_format == "markdown":  # pragma: no branch
            output.append([ANSIThemeStr("## Commands:", "description")])
    elif globaloptioncount:
        if output_format == "default":
            output.append([ANSIThemeStr("Global Options:", "description")])
        elif output_format == "markdown":  # pragma: no branch
            output.append([ANSIThemeStr("## Global Options:", "description")])

    for key, value in commandparser_types.commandline.items():
        if key in ("__default", "extended_description", "__*"):
            continue

        if key.startswith("spacer"):
            commands.append(([ANSIThemeStr("  ", "default")],
                             [ANSIThemeStr("  ", "default")]))
            continue

        if key == "__global_options" and has_commands:
            if output_format == "default":
                commands.append(([ANSIThemeStr("Global Options:", "description")],
                                 [ANSIThemeStr("", "default")]))
            elif output_format == "markdown":  # pragma: no branch
                commands.append(([ANSIThemeStr("### Global Options:", "description")],
                                 [ANSIThemeStr("", "default")]))

        tmp: list[ANSIThemeStr] = []
        separator = "|"
        for cmd in deep_get(value, DictPath("command"), []):
            if key.startswith("__"):
                continue

            if tmp:
                tmp.append(ANSIThemeStr(f"{separator}", "separator"))
            elif output_format == "markdown":
                tmp.append(ANSIThemeStr("`", "command"))
            tmp.append(ANSIThemeStr(f"{cmd}", "command"))
        if tmp and output_format == "markdown":  # pragma: no branch
            tmp.insert(0, ANSIThemeStr("### ", "command"))
            tmp.append(ANSIThemeStr("`", "command"))

        values = deep_get(value, DictPath("values"))
        if values is not None:
            if output_format in ("default", "short"):
                tmp.append(ANSIThemeStr(" ", "default"))
            elif output_format == "markdown":  # pragma: no branch
                tmp.append(ANSIThemeStr(" _", "default"))
            tmp += list(values)
            if output_format == "markdown":
                tmp.append(ANSIThemeStr("_", "default"))

        tlen = themearray_len(tmp)
        maxlen = max(maxlen, tlen)
        if tlen:
            description = deep_get(value, DictPath("description"))
            if output_format in ("default", "short"):
                commands.append((tmp, description))
            elif output_format == "markdown":  # pragma: no branch
                description.insert(0, ANSIThemeStr("#### ", "default"))
                commands.append((tmp, description))
                commands.append(([ANSIThemeStr("  ", "default")],
                                 [ANSIThemeStr("  ", "default")]))

        extended_description = deep_get(value, DictPath("extended_description"), [])
        if output_format == "default":
            for line in extended_description:
                commands.append(([ANSIThemeStr("", "default")], line))
        elif output_format == "markdown":  # pragma: no branch
            tmp_extended_description = []
            for i, line in enumerate(extended_description):
                if i:
                    tmp_extended_description += [ANSIThemeStr(" ", "default")]
                tmp_extended_description += line
            if tmp_extended_description:
                commands.append(([ANSIThemeStr("", "default")], tmp_extended_description))
                commands.append(([ANSIThemeStr("  ", "default")],
                                 [ANSIThemeStr("  ", "default")]))

        options = deep_get(value, DictPath("options"), [])
        for option in options:
            if output_format == "short":
                continue
            if deep_get(value, DictPath(f"options#{option}#hidden"), False):
                continue
            indent = ""
            if tmp:
                indent = "  "
            tmp2 = [ANSIThemeStr(f"{indent}", "option")]
            if key.startswith("__"):
                if output_format == "default":
                    tmp2.append(ANSIThemeStr(f"  {option}", "option"))
                elif output_format == "markdown":  # pragma: no branch
                    tmp2.append(ANSIThemeStr(f"  __`{option}`__", "option"))
            else:
                if output_format == "default":
                    tmp2.append(ANSIThemeStr(f"{option}", "option"))
                elif output_format == "markdown":  # pragma: no branch
                    tmp2.append(ANSIThemeStr(f"__`{option}`__", "option"))
            values = deep_get(value, DictPath(f"options#{option}#values"))
            if values is not None:
                tmp2.append(ANSIThemeStr(" ", "default"))
                if output_format == "markdown":
                    tmp2.append(ANSIThemeStr("_", "default"))

                tmp2 += list(values)
                if output_format == "markdown":
                    tmp2.append(ANSIThemeStr("_", "default"))
            tlen = themearray_len(tmp2)
            maxlen = max(maxlen, tlen)
            description = deep_get(value, DictPath(f"options#{option}#description"))
            if indent:
                description = [ANSIThemeStr(indent, "default")] + description
            if output_format == "markdown":
                description.append(ANSIThemeStr("  ", "default"))
            commands.append((tmp2, description))
            extended_description = deep_get(value,
                                            DictPath(f"options#{option}#extended_description"), [])
            for line in extended_description:
                if indent:
                    commands.append(([ANSIThemeStr("", "default")],
                                     [ANSIThemeStr(indent, "default")] + line))
                else:
                    commands.append(([ANSIThemeStr("", "default")], line))
            commands.append(([ANSIThemeStr("  ", "default")],
                             [ANSIThemeStr("", "default")]))

    # cmd[0]: formatted cmd/option
    # cmd[1]: formatted description
    for cmd in commands:
        if output_format in ("default", "short"):
            if themearray_len(cmd[0]) > 27 or \
                    themearray_len(cmd[0]) + 2 + themearray_len(cmd[1]) > 79 or \
                    themearray_len(cmd[1]) > 51:
                output.append(cmd[0])
                string = themearray_ljust([ANSIThemeStr("", "default")], 29) + cmd[1]
                output.append(string)
                if debug and themearray_len(string) > 79:
                    ansithemeprint([ANSIThemeStr("Warning", "warning"),
                                    ANSIThemeStr(": The helptext string:", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr("“", "emphasis")] + string
                                   + [ANSIThemeStr("“", "emphasis")], stderr=True)
                    ansithemeprint([ANSIThemeStr(f"is {themearray_len(string)} characters long; "
                                                  "it should be < 80 characters; "
                                                  "please file a bug report.\n\n", "default")],
                                   stderr=True)
                    sys.exit(errno.EINVAL)
            else:
                string = themearray_ljust(cmd[0], 29) + cmd[1]
                output.append(string)
        elif output_format == "markdown":  # pragma: no branch
            if ansithemearray_to_str(cmd[0], color=False).strip():
                output.append(cmd[0])
            output.append(cmd[1])

    if "extended_description" in commandparser_types.commandline:
        output.append([ANSIThemeStr("", "default")])
        output += list(deep_get(commandparser_types.commandline,
                                DictPath("extended_description"), []))

    # Post-processing filtering
    for line in output:
        if output_format == "markdown":
            tmpline = []
            for segment in line:
                themeref = segment.get_themeref()
                rstring = str(segment)
                rstring = rstring.replace("<", "\\<")
                rstring = rstring.replace(">", "\\>")
                rstring = rstring.replace("`", "\\`")
                if themeref in ("option", "emphasis"):
                    stripped, lcount = lstrip_count(rstring, " ")
                    stripped, rcount = rstrip_count(stripped, " ")
                    if stripped and not stripped.startswith("__") and not stripped.endswith("__"):
                        rstring = "".ljust(lcount) + f"__{stripped}__" + "".ljust(rcount)
                        segment = ANSIThemeStr(rstring, themeref)
                elif themeref in ("argument", "note", "path", "version"):
                    stripped, lcount = lstrip_count(rstring, " ")
                    stripped, rcount = rstrip_count(stripped, " ")
                    if stripped and not stripped.startswith("_") and not stripped.endswith("_"):
                        rstring = "".ljust(lcount) + f"_{stripped}_" + "".ljust(rcount)
                        segment = ANSIThemeStr(rstring, themeref)
                # elif themeref not in ("command", "default",
                #                       "description", "programname", "separator"):
                #     sys.exit(themeref)
                tmpline.append(segment)
            line = tmpline
        ansithemeprint(line)

    return 0
