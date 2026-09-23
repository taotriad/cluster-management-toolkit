#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
# Requires: python3-jinja2

"""
Generate a stub view-file for a Kubernetes resource.
"""

import os
import re
import sys


try:  # pragma: no cover
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import jinja2; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install jinja2`; aborting.")


# pylint: disable-next=too-many-locals
def main() -> None:
    """
    Main function for the program.
    """
    # Before doing anything else, make sure that the user is not running as root
    if os.geteuid() == 0:
        sys.exit("CRITICAL: This program should not be run as the root user; aborting.")

    # This program should be called with the path to the directory to process .j2 files in
    # as well as a path to the directory that holds the variables to use in substitutions.
    if len(sys.argv) != 5:
        sys.exit("Usage: generate_viewfile.py NAME APIVERSION NAMESPACED KIND")

    name = sys.argv[1]
    apiversion = sys.argv[2]
    api_family = apiversion.split("/", maxsplit=1)[0]
    namespaced = sys.argv[3]
    kind = sys.argv[4]

    tmp = re.findall("([A-Z][a-z0-9]*)", kind)
    listview_name = ""

    if not tmp:
        sys.exit(f"Could not figure out how to parse the kind {kind}")

    listview_name = " ".join(tmp)
    if not listview_name.endswith("s"):
        listview_name += "s"

    infoview_name = ""

    if not tmp:
        sys.exit(f"Could not figure out how to parse the kind {kind}")

    infoview_name = " ".join(tmp)
    infoview_name += " Info"

    template_path = f"{os.getcwd()}/devtools"

    if namespaced.lower() == "true":
        template_file = "viewfile_namespaced.yaml.j2"
    else:
        template_file = "viewfile.yaml.j2"

    destpath = f"views/{kind}.{api_family}.yaml"

    if os.path.exists(destpath):
        sys.exit(f"Error: {destpath} exists; aborting.")

    # Initialise Jinja2
    environment = Environment(loader=FileSystemLoader(template_path),
                              keep_trailing_newline=True,
                              autoescape=select_autoescape())
    context = {}

    context["kind"] = kind
    context["api_family"] = api_family
    context["name"] = name
    context["listview_name"] = listview_name
    context["infoview_name"] = infoview_name

    template = environment.get_template(template_file)
    rendered = template.render(context)

    with open(str(destpath), mode="w", encoding="utf-8") as f:
        f.write(rendered)


if __name__ == "__main__":
    main()
