# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def format_controller(controller: tuple[tuple[str, str], str], show_kind: str) -> tuple[str, str]:
    """
    Reformat a controller kind + name tuple.

        Parameters:
            controller ((str, str), str): The controller kind
            show_kind (str): "short" / "full" / "mixed"
        Returns:
            (str, str): A tuple with a possibly reformatted controller kind + name
    """
    pod = controller[1]

    match show_kind:
        case "":
            fmt_controller = ""
        case "short":
            fmt_controller = controller[0][0]
        case "full":
            fmt_controller = ".".join(controller[0])
        case "mixed":
            # Strip the API-group for standard controllers,
            # but show for custom controllers
            if controller[0] in (("StatefulSet", "apps"), ("ReplicaSet", "apps"),
                                 ("DaemonSet", "apps"), ("Job", "batch"),
                                 ("CronJob", "batch"), ("Node", "")):
                fmt_controller = controller[0][0]
            else:
                fmt_controller = ".".join(controller[0])
        case _:
            raise ValueError(f"unknown value passed to show_kind: {show_kind}")

    fmt_controller = fmt_controller.removesuffix(".")

    return (fmt_controller, pod)
