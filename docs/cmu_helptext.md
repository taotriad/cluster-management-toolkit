# ___`cmu`___ __`COMMAND`__ _`[OPTION]`_... _`[ARGUMENT]`_...

UI for managing Kubernetes clusters.

## Commands:
### `view` _[_PATH_]_
#### Open file viewer
  
  __`--format`__ __FORMAT__
  File FORMAT  
  If the file format cannot be deduced from
  the name this option can be used to specify
  the file format. Valid formats are:
  _bash_, _cel_, _crt_, _css_, _docker_, _dmesg_, _diff_|_patch_,
  _html_, _ini_, _javascript_|_js_, _json_,_markdown_|_md_,
  _ndjson_, _powershell_|_ps1_, _promql_, _python_|_py_,
  _shell_|_sh_, _svg_, _toml_, _xhtml_, _xml_, _yaml_

### `VIEW` _[_NAMESPACE/_]_OBJECT_[_:_[_MEMBER_]]_
#### start in VIEW for _OBJECT_
  
Sometimes _OBJECT_ may need to be qualified by using _NAMESPACE_, but if there's only one unique match cmu will open that match. If an object has members (containers or configmaps), these can be opened using the _:MEMBER_ syntax. If there's only one member specifying _:_ is sufficient.
  
  
### `list-namespaces`
#### List valid namespaces and exit
  
  __`--color`__ __WHEN__
  WHEN should the output use ANSI-colors  
  Valid arguments are:
  _always_ (always color the output)
  _auto_ (color the output when outputting
  to a terminal)
  _never_ (never color the output)

  __`--format`__ __FORMAT__
  Format the output as FORMAT  
  Valid formats are:
  _default_ (default format)
  _csv_ (comma-separated values)
  _ssv_ (space-separated values)
  _tsv_ (tab-separated values)

### `list-views`
#### List view information and exit
  
  
### Global Options:

  __`--read-only`__
disable all commands that modify state  

  __`--disable-kubernetes`__
disable Kubernetes support  
This option disables Kubernetes support;
this is typically only useful if you use
cmu to manage an Ansible inventory

  __`--kube-config`__ __PATH__
_PATH_ to kubeconfig file to use  
Use _PATH_ as kubeconfig; by default
_/home/tao/.kube/config_ is used

  __`--namespace`__ __NAMESPACE__
only show objects in namespace _NAMESPACE_  

  __`--theme`__ __THEME__
_THEME_ to use  

  
### `help` __COMMAND__
#### Display help about _COMMAND_ and exit
  
### `help|--help`
#### Display this help and exit
  
  __`--format`__ __FORMAT__
  Output the help as _FORMAT_ instead  
  Valid formats are:
  _default_, _short_, _markdown_

### `version|--version`
#### Output version information and exit
  

If _VIEW_ is not specified cmu will show a list with all available views

_Note_: _cmt.yaml_ or a file in _cmt.yaml.d_ can be used to set a _VIEW_ to use
if no view is specified. To override this and open the selector instead,
simply use “cmu _selector_“.
