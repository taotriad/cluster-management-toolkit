# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Set/get the programname for use in validator error messages.
"""

from typing import cast

programname: str | None = None  # pylint: disable=invalid-name


def get_programname() -> str:
    """
    Return the programname.
    """
    return cast(str, programname)


def set_programname(programname_: str) -> None:
    """
    Set the name of the calling program, to ensure that error messages are correct.
    Note: This should be removed; libraries should not print error messages
    (Hmmm, but it might still return it formatted or send it to cmtlog?)

        Parameters:
            programname_ (str): The name of the program
    """
    global programname  # pylint: disable=global-statement
    programname = programname_
