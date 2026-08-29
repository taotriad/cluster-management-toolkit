# This directory holds parser rules

Every file is a list of rules; even files with only one rule must be a list.
If a parser rule should be applied multiple times, such as when filtering out
timestamps, just specify the same rule again.

If you need multiple different rules for a resource depending on the pod/container
combination, but want them all listed as the same parser you can specify the
same name multiple times. Note, however, that such rules cannot be shown
in the selector.


## Rules for the matchkeys section

* `pod_name` and `container_name` uses match-position indicators when matching;
  the rules are as follows:
  | Syntax | Match type      |
  | ------ | --------------- |
  | Name   | `.startswith()` |
  | ^Name  | `.startswith()` |
  | Name$  | `.endswith()`   |
  | ^Name$ | `==`            |
* `image_name` always uses `.startswith()`. When processing `image_name` the name
  of the container will first have its server stripped from the path if `image_name`
  starts with `/`. If you want a verbatim match, for instance if you want to use
  a separate parser-file for internal builds, you can skip the leading `/`.
* `image_regex` can be used to match the image-name by regex instead.
* `container_type` can be either `Container` or `InitContainer`; default is `Container`.


## Supported parser-rules

| Rule name                      | Summary                                                            | Options                                                                                     |
| :----------------------------- | :----------------------------------------------------------------- | :------------------------------------------------------------------------------------------ |
| bracketed_severity             | Extract severity formatted as `[severity]`                         | severity(default)                                                                           |
| custom_line                    | Custom block scanner                                               | *block_start*, *block_end*, eof, formatter, regex, severity(default,overrides)              |
| custom_splitter                | Custom line splitter                                               | *regex*, severity(field,overrides,transform), facility(fields,separators), *message(field)* |
| directory                      | Formatter for output from `ls`                                     | **N/A**                                                                                     |
| expand_event                   | Expand event message                                               | **N/A**                                                                                     |
| glog                           | Extract severity and facility from output from `glog`              | **N/A**                                                                                     |
| http                           | Format log messages from various HTTP servers                      | **N/A**                                                                                     |
| iptables                       | Format output from `iptables`                                      | **N/A**                                                                                     |
| json                           | Format single-line *JSON*                                          | error, facility, message, severity, timestamp, version                                      |
| json_event                     | Format events logged as single-line *JSON*                         | error, facility, message, severity, timestamp, version                                      |
| json_with_leading_message      | Format *JSON* preceded by a plain-text message                     | error, facility, message, severity, timestamp, version                                      |
| key_value                      | Format data in *key=value* format                                  | allow_bare_keys, newlines, error, facility, message, severity, timestamp, version           |
| key_value_with_leading_message | Format data in *key=value* format preceded by a plain-text message | allow_bare_keys, newlines, error, facility, message, severity, timestamp, version           |
| modinfo                        | Format output from `modinfo`                                       | **N/A**                                                                                     |
| override_severity              | Based on match-rules, override the severity of a line              | *severity(overrides)*                                                                       |
| seconds_severity_facility      | Formatter for data in `[  0.0123s] INFO ThreadID(01) ...` format   | **N/A**                                                                                     |
| strip_ansicodes                | Strip *ANSI-codes* from log message                                | **N/A**                                                                                     |
| sysctl                         | Format output from `sysctl`                                        | **N/A**                                                                                     |
| tab_separated                  | Format tab-separated data; will format trailing `JSON`-format      | error, message, version                                                                     |
| ts_8601                        | Strip timestamps resembling *ISO-8601* format                      | **N/A**                                                                                     |

Options in **bold** are mandatory. Paranthesis are an option indicates that it has subrules, of which only the indicated ones are supported.


### Options

#### allow_bare_keys

```
allow_bare_keys: (str) Should keys allowed to be of the type *key* rather than *key=value* (valid: all, capitalize, lowercase, uppercase)
```


#### block_end

```
block_end (list):
  - matchtype: (str) The type of match to use (valid: contains, empty, endswith, exact, match, search, startswith)
    matchkey: (str) The string to use when applying the matchtype
    matchline: (str) The line a match can start at (valid: any, first)
    format_block_start: (bool) Should the line that matched the expression be formatted?
  ...
```


#### block_start

```
block_start (list):
  - matchtype: (str) The type of match to use (valid: contains, endswith, exact, match, search, startswith)
    matchkey: (str) The string to use when applying the matchtype
    matchline: (str) The line a match can start at (valid: any, first)
    format_block_start: (bool) Should the line that matched the expression be formatted?
  ...
```


#### diff_space

```
diff_space: (int) Spaces between diff signs and data
```


#### error

```
error:
  keys (list):
    - (str) The keys in a structure log message that may contain error messages
    ...
  tags (dict):
    (str, str) A dict of tags that should be regarded as error tags
    ...
```


#### facility

```
facility:
  fields: (int) The regex capture groups to get the facilities from **indexed from 1**
  keys (list):
    - (str) The keys in a structure log message that may contain facilities
    ...
  separators (list):
    - (str) The separators between facilities if multiple facilities are found
    ...
```


#### formatter

```
formatter: (str) A formatter to use when formatting the content of block from custom_line
                 (valid: format_ansible, format_diff, format_generic, format_none, format_python_traceback, format_yaml, reformat_json; default: format_generic)
```


#### indent

```
indent: (int) Indentation before diff
```


#### message

```
message:
  field: (int) The regex capture group to get the message from **indexed from 1**
  keys (list):
    - (str) The keys in a structure log message that may contain messages
    ...
```


#### regex

```
regex: (str) A regular expression to use when extracting information;
             in most cases the regex corresponds to the field(s) arguments,
             but in a few cases only one match-group is expected to be non-null,
             and thus the first match group will be used (if any).
```


#### severity

```
severity:
  default: (str) The default loglevel to use (valid: debug, info, notice, warning, err, crit, alert, emerg)
  highlight_reason: (bool) Should Event reason be highlighted?
  keys (list):
    - (str) The keys in a structured log message that may contain the severity
    ...
  overrides (list):
    - matchtype: (str) The type of match to use (valid: contains, endswith, exact, regex, startswith)
      matchkey: (str) The string to use when applying the matchtype
      loglevel: (str) The loglevel to override with (valid: debug, info, notice, warning, err, crit, alert, emerg)
    ...
```


#### version

```
version:
  keys (list):
    - (str) The keys in a structure log message that may contain versions
    ...
```


## Rule-file structure

```
- name: name of the parser (displayed as parser name)
  show_in_selector: Should the parser be shown in the override selector?
    (default: false; Unless the parser is very generic you always want to set this to false)
  matchkeys:
  - pod_name: pod match string
    container_name: container match string
    image_name: image match string
    image_regex: image match regex
    container_type: (Container | InitContainer)
  parser_rules:
  - name: rule
    ...
    ...
```

## Examples

No examples are provided here; instead it's recommended to use the files in this directory as examples,
since they are in active use; some suggested parser-files:

* `kube-app-manager.yaml` (Simple rule-file that extracts severity and facility from *glog*-style messages, then formats the file using the *tab_separated* rule)
* `kube-proxy.yaml` (Formats messages in key=value format that has a leading plain-text message; it allows for lower-case keys lacking a value; it also provides some examples of basic severity overrides)
* `intel-gpu-operator.yaml` (Provides examples of how to use the *custom_line* block scanner, both for generic output and formatted as a diff)

## Validating your parser-file

* `make validate_yaml` validates all *parser-files*, *view-files*, and *themes*, and should always be run after creating or modifying a parser-file.
* `make yamllint` will check the coding-style of your `YAML`-files.

## Special notes

* Currently there's no way to override a leading message without affecting the rest of the structure.
* The rule `tab_separated` expects a leading timestamp; hence it will not work if `ts_8601` is included before that rule.
* While overriding the severity of a structured message normally only changes the formatting of the matching value,
  an exception is made for debug-severity. Messages with debug-severity will have the entire structured message formatted
  as a debug message. This is to ensure that it's clear the message is purely for debugging purposes.

> [!IMPORTANT]
> Since log-messages come from a wide variety of sources, and the components may change over time,
> it's quite likely that the parser-files will handle all future logs even if they worked when written.
> The parser-files were written under observed conditions; this means that it's quite probable that
> there are plenty of cases that are not covered.
>  
> Some parser-rules are rather complex and thus can be a bit brittle, most notably the block-parsers.
> If they encounter unexpected behaviour they will (hopefully) revert to unformatted logs.
