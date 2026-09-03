# TODO

## view-files

* [ ] v0.8.11:
  * [ ] Unify naming standards:
    * [ ] create_object()
    * [ ] patch_object()
    * [ ] delete_object()
  * [ ] Unify calling conventions:
    * [ ] Everything should be "action", not "actionfunc", etc.
    * [ ] Use the same template format for both create_object() and patch_object()
  * [ ] Add selector list as input method, with sources being either obj,
        lookup, or const.
  * [ ] Make inputs a list; this way we can get more than one input
        without having to make a multi-input widget (though such a widget would
        be really nice to have).
* [ ] v0.9.x:
  * [ ] Move field_templates and built-in views to views.

## General

* [ ] v0.9.x:
  * [ ] Introduce `.kube/current-context` and have all clusters in `.kube/config.d/clustername.yaml`.
* [ ] Future:
  * [ ] When running either cmt or cmu, check whether `.ssh/id_*.pub` is in authorized_keys.
        in `.cmt/ansible/inventory.yaml`; if not, add it.
  * [ ] Add `--dry-run` support for more commands.
  * [ ] itemgetters should ideally either have feature parity, or (preferred),
        be a strict subset of listgetters; check what would be necessary to achieve
        the latter.
  * [ ] get_obj() is a monstrosity and needs to be refactored.
  * [ ] Views should be able to define dependent subviews; this way `[ctrl] + R` can be made to work
        even in subviews; additionally toplevel artificial views, such as ResourceView,
        should always be reloaded.
  * [ ] We need a sortable: true|false field to go along with reversible: true|false.
  * [ ] sortorder_reverse: true|false might be a higher level property?

## commandparser and cmtvalidators

* [ ] v0.9.x:
  * [ ] Investigate whether using argparse would be better than using our own parser;
        it would require some effort to rewrite, but it would standardise things.
        After a rewrite only the helptexts would need to be customised.
  * [ ] __commandparser__: Add support for aliases.
  * [ ] __commandparser__: Add support for global vs local options.
  * [ ] __commandparser__: Add support for short options.
  * [ ] __commandparser__: Loosen the rules for option positions; it should be possible
        to have the options interspersed with, or after the arguments.
  * [ ] __commandparser__: Do partial argument splitting already in the command parser;
        since we're doing argument validation in the command parser we know what
        separators are used.
  * [ ] __cmtvalidators__: Further improve the validation, with types such as
        Kubernetes resource type, resource name, etc.
  * [ ] Ideally the commandparser + validator combo should be able to validate
        namespace/name:subresource for pods & configmaps without resorting to regex.

## curses_helper

* [ ] v0.8.11:
  * [ ] List- and logpads need to be able to have a title; it can be quite
        confusing to see an empty list- or logpad without knowing its purpose.
* [ ] v0.9.x:
  * [ ] We need to rewrite the UI to remove reliance on stdscr; stdscr should just be blank
        canvas. This solves all the rescaling issues, as well as limitations with what characters
        can go where, etc.
    * [ ] Borders should be drawn by curses_helper, not by win.border().
    * [ ] The border should be part of the bottom-most canvas and only needs redrawing if we
          resize the window or toggle borders.
    * [ ] Scrollbars need their own windows.
* [ ] v1.0.x:
  * [ ] UI extensions:
    * [ ] It should be possible to have multiple info-, list-, and logpads, and to switch between them.

## cmt-install

* [ ] v0.9.x:
  * [ ] Add dependency on python3-curses on SUSE.
* [ ] Future:
  * [ ] Ensure that we install from a recent version of python when installing python
        dependencies on OpenSUSE/SLES.

## cmu

* [ ] v0.9.x:
  * [ ] Make generic_infogetter consistent WRT to paths:
        `["literal", ["path"], [["alternate_path1"], ["alternate_path2"], "literal"]]`.
* [ ] Future:
  * [ ] Do we need a commandline option for quick switching between views
        and executing some commands?
  * [ ] Do we need a shell prompt? It would require a LOT of work.
  * [ ] It's about time we come up with a good way to group views in terms
        of what's enabled. For instance it's highly unlikely that we'll have OpenShift
        deployed at the same time as Harvester / Rancher / Longhorn.
    * [ ] Bundle all Core APIs into one file and load them all using secure_read_yaml_all();
          this *should* lead to a slight performance improvement;
          note that the files should be kept separate and only bundle upon "build".
  * [ ] In Node and Inventory Info view we should provide a way to list all logs
        related to the host, and a shortcut to jump to that log.
  * [ ] All use of curses should be abstracted away; ideally cmu should be able to use
        a variety of different toolkits to present its data.
  * [ ] All generators and other functions used to extract data should be removed from cmu;
        that way we don't have to duplicate functionality between cmu and cmt.
  * [ ] Make extended facilities non-repeating in the same way that regular facilities are
        (see podlog).

## cmtinv

* v0.9.x:
  * [ ] Optionally limit rebuild-inventory to a subset of clusters.

## cmtadm

* [ ] v0.9.x:
  * [ ] prepare_passwordless_ansible won't work on localhost; we're not passing the password,
        and the password might not be the same on the remote system and the local system anyway.
  * [ ] Add `pre-upgrade-check` that checks whether relevant config files (notably containerd)
        are compatible with new settings. Also check whether the cluster currently uses
        any APIs that are deprecated, and any deployments that are known to be unsupported on
        newer versions of Kubernetes. Config-checks needs to check all nodes, not just
        the control plane.
  * [ ] troubleshoot:
    * [ ] Check that the config-files as installed/created at install time by cmtadm/cmt
          are in sync with what's on the machines in the cluster at present, and if not,
          warn about the difference.
          The differences *may* be intentional, so we cannot indiscriminately overwrite them,
          but the user should at least be aware of the differences (we could even show a diff
          if `--verbose` is passed) and provide a helpful message about what playbook to
          run to update the files.
    * [ ] Add a security warning about file permissions.
    * [ ] Add a security warning ansible_pass being used in cmtconfig.

## logparser

* [ ] v0.9.x:
  * [ ] Line too long shouldn't override severity. Ideally max line length should:
    1. Be configurable.
    2. Trigger line splitting into remnants.
  * [ ] For key_value_with_leading_message when having allow_bare_keys enabled
        we should only allow booleans and integers to be unquoted. Otherwise we
        might end up with regular strings split over multiple lines.
  * [ ] All handling of message needs to be rewritten; as soon as a message gets formatted as a themearray
        it can no longer be processed further.
  * [ ] Rewrite key_value; the parser is overly complex at the moment; it needs to be simplified
        and have fewer special cases.

## Testability

* [ ] v0.9.x:
  * [ ] To ensure that we can test changes to list- and info-getters, as well as logparsers,
        we should keep example resources and logs for app resources we add support for.
        This would also enable us to release-test all view-files and thus gain much better test coverage.
* [ ] Future:
  * [ ]For testability of cmu we need to implement input injection support.
