# Project roadmap

## Principal goals for 2026

The main goal for 2026 is to get __Cluster Management Toolkit for Kubernetes__ (__CMT__)
ready for mainstream adoption. The code quality should be such that it does not
scare off first time contributors. It must be at least _theoretically possible_
to distribute __CMT__ as a part of a Linux distribution
(there's obviously no guarantee that any distro will distribute it).

Note: the test coverage for `*.py` will drop whenever code
is moved from `cmt`, `cmtadm`, `cmu`, and `cmtinv` to `*.py`, until
tests have been added for the moved code.

## Q1 roadmap

* _General_:
    * [x] Release __CMT__ v0.8.7.
      * [x] Fix Issue #9 (uninstall-cni fails if helper or configuration doesn't exist).
    * [x] Use Pygments to do syntax highlighting instead of our own hackish solution.
      * [x] Custom output plugin for ThemeArray.
      * _Note:_ If a format has a pre-existing Pygments lexer it's highly likely
        that support can and will be added on request.
    * [x] Convert formatters that can use Pygments' built-in lexers.
      * [x] ASCII armored text (certificates, keys, etc).
      * [x] INI
      * [x] JSON
      * [x] NGINX
      * [x] PowerShell
      * [x] Python Tracebacks
      * [x] Shell Scripts (POSIX sh, bash, dash, posh, zsh)
      * [x] TOML
      * [x] XML
      * [x] YAML
    * [x] Convert formatters that can use built-in lexers augmented by additional filters.
      * [x] Markdown (built-in + custom)
    * [x] Convert formatters that needs custom lexers.
      * [x] known_hosts
      * [x] Mosquitto

## Q2 roadmap

* _General_:
    * [ ] Refactor libraries in a way that makes a __CMT__ release possible. This includes:
        * [ ] Rewrite all logging to use Python's builtin logging and register a MemoryHandler;
          this way we get flushing whenever the severity is high enough.
    * [ ] Register KeyboardInterrupt handlers in all executables to do proper shutdown
      and print helpful messages.
    * [ ] Distribute as:
        * [ ] Source code.
        * [ ] Debian package.
        * [ ] Possibly via PIP?
    * Continue work on moving from custom lexers to Pygments.
    * [ ] Convert formatters that can use Pygments' built-in lexers.
      * [ ] NDJSON (just needs to be verified to work)
      * [ ] Perl
      * [ ] Python
      * [ ] Ruby
    * [ ] Convert formatters that needs custom lexers.
      * [ ] CEL
      * [ ] HAProxy
      * [ ] CaddyFile
      * [ ] FluentBit

* _Accessibility_:
    * [ ] Ensure that the Colour Vision Deficiency theme covers all relevant data.
      Using colour coding in conjunction with CVD is acceptable, but only when important
      information (severity, etc.) is conveyed through other means.
    * [ ] Provide a high-contrast theme.
* _cmu_:
    * [ ] UI refactoring: Use the generic input handler from curses helper for all input.
    * [ ] UI refactoring: Unified helptext generation.
    * [ ] General refactoring: Start working on turning _cmu_ into a generic UI framework
      that takes YAML files that describe list, info, and data (logpad) views.
      The descriptions should include helpers to use to fetch data,
      helpers to use to process that data, a list of actions that can be performed
      on that data, as well as information about what, if any, relationships the data
      has with data in other info views.

## Q3 roadmap

* _General_:
    * [ ] Go through all input helpers, formatters, etc., to see which, if any, we can merge.
    * [ ] tests: Achieve 55% test coverage for `*.py`.
* _cmu_:
    * [ ] Continue, hopefully conclude, the general refactoring, enabling new _cmt_ functionality.
    * [ ] If possible it should be possible to reinitialise the UI and thus change themes.
      This would let users test what themes they like the most, but more importantly it would
      enable using different themes for different contexts, as a useful reminder about what
      context you're operating in.
* _cmt_:
    * [ ] Once the _cmu_ refactoring has taken place we should be in a good place to
      reuse most of the helpers to implement `cmt get OBJECT`, `cmt describe OBJECT`, etc.

## Q4 roadmap

* TBD

## Backlog

* _Project_:
    * [ ] Get more contributors to ensure that we can meet the basic criteria for OpenSSF
      Best practices. Currently we are gated by the fact that the bus factor is too low,
      reviewers are missing, and other things that require multiple contributors.
    * [ ] Write all documentation needed to meet silver criteria for OpenSSF Best Practices.
      Note that several of the requirements for silver and gold criteria make meeting
      all criteria unlikely, but we should still do our best.
* _cmtadm_:
    * [ ] Support for clusters with virtualised control planes.
    * [ ] Support for having multiple different VM-hosts in the same cluster.
