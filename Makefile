yaml_dirs = parsers themes views playbooks docs/examples sources
python_executables = \
	cmt \
	cmtadm \
	cmt-install \
	cmtinv \
	cmu
python_executables_py = \
	cmt.py \
	cmtadm.py \
	cmt-install.py \
	cmtinv.py \
	cmu.py
python_test_executables = \
	tests/ansibletests.py \
	tests/async_fetch.py \
	tests/atptests.py \
	tests/checkstests.py \
	tests/check_theme_use.py \
	tests/clptests.py \
	tests/cmtlibtests.py \
	tests/cmtlogtests.py \
	tests/cnitests.py \
	tests/coverage_stats.py \
	tests/cursestests.py \
	tests/datatests.py \
	tests/dgtests.py \
	tests/dump_cluster.py \
	tests/dump_logs.py \
	tests/fgtests.py \
	tests/fmttests.py \
	tests/gentests.py \
	tests/infogtests.py \
	tests/iotests.py \
	tests/itemgtests.py \
	tests/khtests.py \
	tests/lgtests.py \
	tests/logtests.py \
	tests/networkiotests.py \
	tests/ogtests.py \
	tests/typetests.py \
	tests/validate_yaml.py \
	tests/validatortests.py
python_unit_tests_ansible = \
	tests/ansibletests.py
python_unit_tests_cluster = \
	tests/async_fetch.py
python_unit_tests = \
	tests/atptests.py \
	tests/checkstests.py \
	tests/clptests.py \
	tests/cmtlibtests.py \
	tests/cmtlogtests.py \
	tests/cnitests.py \
	tests/cursestests.py \
	tests/datatests.py \
	tests/dgtests.py \
	tests/fgtests.py \
	tests/fmttests.py \
	tests/gentests.py \
	tests/infogtests.py \
	tests/iotests.py \
	tests/itemgtests.py \
	tests/khtests.py \
	tests/lgtests.py \
	tests/logtests.py \
	tests/networkiotests.py \
	tests/ogtests.py \
	tests/typetests.py \
	tests/validatortests.py

# The Documents to include in the Markdown Table of Contents (toc)
markdown_toc = \
	Introduction.md \
	Installing_CMT.md \
	Creating_a_cluster_using_a_template_file.md \
	Setup_a_control_plane.md \
	Setup_worker_nodes.md \
	Remove_worker_nodes.md \
	Teardown_a_control_plane.md \
	Helptexts.md \
	Useful_commands.md \
	CMU.md \
	Supported_platforms.md \
	Development.md \
	roadmap/Project_roadmap.md

# F841 is the warning about unused assignments.
# flake8 doesn't recognise "_<variable>" to capture unused return values;
# pylint does, so we rely on that one to handle it instead.
# W503 is for line break before binary operator;
# flake8 warns *both* for breaks before and after.
# Hence we we need to ignore one of those warnings.
# flake8 doesn't give sensible suggestions when using modern style union
# type annotations, so disable E126 and E127.
# H301 is about multiple imports per line, which is a stupid warning.
# H404 and H405 is about docstring formatting that we'll ignore.
# Finally it seems flake8 doesn't seem to recognise when globals are used.
FLAKE8_IGNORE := F841,W503,F824,E126,E127,H301,H404,H405

# Used by ruff to check for future and/or deprecated features
RUFF_PYTHON_VERSION := py311

# Used by pylint to check for future and/or deprecated features
PYLINT_PYTHON_VERSION := 3.11

# W0511 is TODO/XXX/FIXME; we know that these are things that we should fix eventually.
# Hence we do not need warnings about them.
PYLINT_DISABLE := W0511,similarities

# Warn about useless disable
PYLINT_ENABLE := useless-suppression

MYPY_FLAGS := --follow-imports silent --explicit-package-bases --ignore-missing --disallow-untyped-calls --disallow-untyped-defs --disallow-incomplete-defs --check-untyped-defs --disallow-untyped-decorators --warn-redundant-casts --warn-unused-ignores

code-checks: ruff flake8 mypy pylint
checks: ruff bandit regexploit jsonlint yamllint validate_playbooks validate_yaml check_helptexts semgrep

tests: coverage

clean: clean_templates clean_index
	@rm -f bin/*

generate_helptexts: bin
	@for file in $(python_executables); do \
		PYTHONPATH=. ./bin/$${file} help --format markdown > docs/$${file}_helptext.md ;\
	done

generate_mdtoc:
	@(cd docs; ../devtools/mdtoc.py --split-sections $(markdown_toc)) > docs/Table_of_contents.md

check_helptexts:
	@printf -- "\n\nChecking helptexts\n\n" ;\
	for file in $(python_executables); do \
		printf -- "  Checking helptexts for $${file}\n" ;\
		./$${file}.py help --debug > /dev/null && printf -- "    OK\n";\
	done

coverage_stats:
	@tests/coverage_stats.py

coverage-clean:
	@rm -f .coverage ;\
	rm -rf htmlcov

coverage: setup_tests
	@cmd=python3-coverage ;\
	export PYTHONPATH=. ;\
	if command -v python3-coverage > /dev/null 2> /dev/null; then \
		cmd=python3-coverage ;\
	elif command -v coverage-3 > /dev/null 2> /dev/null; then \
		cmd=coverage-3 ;\
	else \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\n  Running: tests/atptests.py --include-clear\n\n" ;\
	$$cmd run --branch --append tests/atptests.py --include-clear --end-at 0 || exit 1 ;\
	printf -- "\n\nRunning $$cmd to check test coverage\n" ;\
	for test in $(python_unit_tests); do \
		printf -- "\n\n  Running: $$test\n\n" ;\
		$$cmd run --branch --append $$test || exit 1 ;\
	done ;\
	$$cmd report --sort cover --precision 1 ;\
	$$cmd html --precision 1 ;\
	$$cmd json

# Run this to augment existing coverage data with tests that require manual interaction
coverage-manual: setup_tests
	@cmd=python3-coverage ;\
	if command -v python3-coverage > /dev/null 2> /dev/null; then \
		cmd=python3-coverage ;\
	elif command -v coverage-3 > /dev/null 2> /dev/null; then \
		cmd=coverage-3 ;\
	else \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check test coverage\n" ;\
	printf -- "\n\n  Running: tests/atptests --include-clear --include-input\n\n" ;\
	$$cmd run --branch --append tests/atptests --include-clear --include-input ;\
	$$cmd report --sort cover --precision 1 ;\
	$$cmd html --precision 1 ;\
	$$cmd json

# Run this to augment existing coverage data with tests that require an ansible inventory
coverage-ansible: setup_tests
	@cmd=python3-coverage ;\
	if command -v python3-coverage > /dev/null 2> /dev/null; then \
		cmd=python3-coverage ;\
	elif command -v coverage-3 > /dev/null 2> /dev/null; then \
		cmd=coverage-3 ;\
	else \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check test coverage\n" ;\
	printf -- "\n\n  Running: tests/cmtlibtests.py --include-ansible\n\n" ;\
	$$cmd run --branch --append tests/cmtlibtests.py --include-ansible || exit 1 ;\
	printf -- "\n\n  Running: tests/ansibletests.py\n\n" ;\
	$$cmd run --branch --append tests/ansibletests.py || exit 1 ;\
	$$cmd report --sort cover --precision 1 ;\
	$$cmd html --precision 1 ;\
	$$cmd json

# Run this to augment existing coverage data with tests that require a running cluster
coverage-cluster: setup_tests
	@cmd=python3-coverage ;\
	if command -v python3-coverage > /dev/null 2> /dev/null; then \
		cmd=python3-coverage ;\
	elif command -v coverage-3 > /dev/null 2> /dev/null; then \
		cmd=coverage-3 ;\
	else \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check test coverage\n" ;\
	printf -- "\n\n  Running: tests/async_fetch.py\n\n" ;\
	$$cmd run --branch --append tests/async_fetch.py || exit 1 ;\
	printf -- "\n\n  Running: tests/dgtests.py --include-cluster\n\n" ;\
	$$cmd run --branch --append tests/dgtests.py --include-cluster || exit 1 ;\
	printf -- "\n\n  Running: tests/fgtests.py --include-cluster\n\n" ;\
	$$cmd run --branch --append tests/fgtests.py --include-cluster || exit 1 ;\
	printf -- "\n\n  Running: tests/lgtests.py --include-cluster\n\n" ;\
	$$cmd run --branch --append tests/lgtests.py --include-cluster || exit 1 ;\
	printf -- "\n\n  Running: tests/khtests.py --include-cluster\n\n" ;\
	$$cmd run --branch --append tests/khtests.py --include-cluster || exit 1 ;\
	printf -- "\n\n  Running: tests/itemgtests.py --include-cluster\n\n" ;\
	$$cmd run --branch --append tests/itemgtests.py --include-cluster || exit 1 ;\
	$$cmd report --sort cover --precision 1 ;\
	$$cmd html --precision 1 ;\
	$$cmd json

coverage-all: coverage coverage-ansible coverage-cluster

# We need to extend the timeout since validation gives up on cmu otherwise.
#
# --exclude-rule python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
# is needed since it flags the risk of cross-site scripting in a file that is:
# a.) Not used to template HTML (it's templating YAML)
# b.) Not accepting external input (it's used by the build-system)
#
# We validate YAML by other means, so skip *.yaml
semgrep_flags :=
semgrep_flags += --exclude-rule "python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2"
semgrep_flags += --exclude "*.yaml" --exclude "*.j2" --exclude "*.json"
semgrep:
	@cmd=semgrep ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check for common security issues in Python code\n" ;\
	printf -- "Note: if this is taking a very long time you might be behind a proxy;\n" ;\
	printf -- "if that's the case you need to set the environment variable https_proxy\n\n" ;\
	$$cmd --version ;\
	$$cmd scan $(semgrep_flags) --timeout=0 --no-git-ignore *.py clustermanagementtoolkit/*.py

# Run this to show code statistics
statistics:
	@cmd=cloc ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
	else \
		cloc --exclude-dir=.ansible,.github,.mypy_cache,.ruff_cache,htmlcov,__pycache__,bin,tests . tests/*.py ;\
	fi ;\
	printf -- "\n" ;\
	cmd=sloccount ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
	else \
		sloccount *.py clustermanagementtoolkit devtools tests/*.py ;\
	fi

bandit:
	@cmd=bandit ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	printf -- "\n\nRunning $$cmd to check for common security issues in Python code\n\n" ;\
	$$cmd --version ;\
	printf -- "\n" ;\
	$$cmd -c .bandit $(python_executables_py) $(python_test_executables) clustermanagementtoolkit/*.py

ruff:
	@cmd=ruff ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	printf -- "\n\nRunning $$cmd to check Python code quality\n\n" ;\
	$$cmd --version ;\
	printf -- "\n" ;\
	for file in *.py devtools/*.py clustermanagementtoolkit/*.py; do \
		printf -- "File: $$file\n" ;\
		$$cmd check --target-version $(RUFF_PYTHON_VERSION) $$file ;\
	done

ruff-tests:
	@cmd=ruff ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	printf -- "\n\nRunning $$cmd to check Python code quality\n\n" ;\
	$$cmd --version ;\
	printf -- "\n" ;\
	for file in $(python_test_executables); do \
		printf -- "File: $$file\n" ;\
		$$cmd check --target-version $(RUFF_PYTHON_VERSION) $$file ;\
	done

pylint:
	@cmd=pylint ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	printf -- "\n\nRunning $$cmd to check Python code quality\n\n" ;\
	$$cmd --version ;\
	printf -- "\n" ;\
	for file in *.py devtools/*.py clustermanagementtoolkit/*.py; do \
		printf -- "File: $$file\n" ;\
		PYTHONPATH=. $$cmd --py-version $(PYLINT_PYTHON_VERSION) --disable $(PYLINT_DISABLE) --enable $(PYLINT_ENABLE) $$file ;\
	done

pylint-markdown:
	@cmd=pylint ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	tmpfile=$$(mktemp); \
	for file in $(python_executables_py) clustermanagementtoolkit/*.py; do \
		result=$$(PYTHONPATH=. $$cmd --py-version $(PYLINT_PYTHON_VERSION) --disable $(PYLINT_DISABLE) --enable $(PYLINT_ENABLE) $$file | grep "Your code" | sed -e 's/Your code has been rated at //;s/ (previous run.*//') ;\
		row="$$file | $$result\n" ;\
		printf -- "$$row" >> $${tmpfile} ;\
	done && \
	./mdtable.py --bold-regex "^\s*\d\.\d\d/10" $${tmpfile} "=Source file" "Score=" && rm $${tmpfile}

pylint-tests:
	@cmd=pylint ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	printf -- "\n\nRunning $$cmd to check Python code quality\n\n" ;\
	for file in $(python_test_executables); do \
		printf -- "File: $$file\n" ;\
		PYTHONPATH=. $$cmd --py-version $(PYLINT_PYTHON_VERSION) --disable $(PYLINT_DISABLE) --enable $(PYLINT_ENABLE) $$file ;\
	done

flake8:
	@cmd=flake8 ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	printf -- "\n\nRunning $$cmd to check Python code quality\n\n" ;\
	$$cmd --version ;\
	printf -- "\n" ;\
	$$cmd --ignore $(FLAKE8_IGNORE) --max-line-length 100 --statistics *.py  devtools/*.py clustermanagementtoolkit/*.py && printf -- "OK\n\n" ;\
	printf -- "\n\nRunning $$cmd to check Python test case code quality\n\n" ;\
	$$cmd --version ;\
	printf -- "\n" ;\
	$$cmd --ignore $(FLAKE8_IGNORE) --max-line-length 100 --statistics $(python_test_executables) && printf -- "OK\n\n"

regexploit:
	@cmd=regexploit-py ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed (install with 'pipx install regexploit' or pipx install --proxy <proxy> regexploit'); skipping.\n\n\n" ;\
		exit 0 ;\
	fi ;\
	printf -- "\n\nRunning $$cmd to check for ReDoS attacks\n\n" ;\
	printf -- "Checking executables\n" ;\
	$$cmd $(python_executables_py) $(python_test_executables) &&\
	printf -- "\nChecking libraries\n" ;\
	$$cmd clustermanagementtoolkit/*.py

jsonlint:
	@cmd=jsonlint-php ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check that all JSON is valid\n\n"; \
	printf -- "\n" ;\
	$$cmd tests/schemas/*.json

yamllint:
	@cmd=yamllint ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check that all YAML is valid\n\n"; \
	$$cmd --version ;\
	printf -- "\n" ;\
	for dir in $(yaml_dirs); do \
		for file in $$(ls $${dir}); do \
			if [ ! $${file##*.} = "yaml" ]; then \
				continue;  \
			fi; \
			if [ $${file} = "__resource_type_index.yaml" ]; then \
				continue;  \
			fi; \
			$$cmd $${dir}/$${file}; \
		done; \
	done; \
	$$cmd cmt.yaml

# Note: we know that the code does not have complete type-hinting,
# hence we return 0 after each test to avoid it from stopping.
mypy:
	@cmd=mypy ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check Python typing\n\n"; \
	$$cmd --version ;\
	printf -- "\n" ;\
	for file in $(python_executables_py) clustermanagementtoolkit/*.py; do \
		$$cmd $(MYPY_FLAGS) $$file || true; \
	done

# Note: we know that the code does not have complete type-hinting,
# hence we return 0 after each test to avoid it from stopping.
mypy-tests:
	@cmd=mypy ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check Python typing\n\n"; \
	$$cmd --version ;\
	printf -- "\n" ;\
	for file in $(python_test_executables); do \
		$$cmd $(MYPY_FLAGS) $$file || true; \
	done

# Note: we know that the code does not have complete type-hinting,
# hence we return 0 after each test to avoid it from stopping.
mypy-markdown:
	@cmd=mypy ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	tmpfile=$$(mktemp); \
	for file in $(python_executables_py) clustermanagementtoolkit/*.py; do \
		result=$$($$cmd $(MYPY_FLAGS) $$file | grep -E "^Found|^Success") ;\
		row="$$file | $$result\n" ;\
		printf -- "$$row" >> $${tmpfile} ;\
	done && \
	./mdtable.py --bold-regex "^\s*Found.*errors" $${tmpfile} "=Source file" "=Score" && rm $${tmpfile}

validate_yaml: build_templates
	@printf -- "\n\nRunning validate_yaml to check that all view-files/parser-files/theme-files are valid\n\n"; \
	./tests/validate_yaml.py --exclude views/__event_reasons.yaml,views/__resource_type_index.yaml,parsers/configmaps.yaml,parsers/BUNDLE.yaml

validate_playbooks:
	@cmd=ansible-lint ;\
	if ! command -v $$cmd > /dev/null 2> /dev/null; then \
		printf -- "\n\n$$cmd not installed; skipping.\n\n\n"; \
		exit 0; \
	fi; \
	printf -- "\n\nRunning $$cmd to check that all Ansible playbooks are valid\n\n"; \
	$$cmd --version 2> /dev/null ;\
	printf -- "\n" ;\
	$$cmd playbooks/*.yaml

export_src:
	git archive --format zip --output ~/cmt-$(shell date -I).zip origin/main

parser_bundle:
	@printf -- "Building parser bundle\n" ;\
	rm -f parsers/BUNDLE.yaml; \
	for file in parsers/*.yaml; do \
		cat $$file >> parsers/BUNDLE.yaml; \
	done

setup_tests:
	@export PYTHONPATH=. ;\
	(cd tests ;\
	  test -d testpaths || mkdir testpaths );\
	(mkdir -p tests/testlogs/2023-05-06_16:02:39.012047_uptime ;\
	 cp playbooks/uptime.yaml tests/testlogs );\
	(cd tests/testpaths ;\
	 test -f cmt.yaml || printf -- "Debug:\n  developer_mode: true" > cmt.yaml ;\
	 test -d cmt.yaml.d || mkdir cmt.yaml.d ;\
	 test -f cmt.yaml.d/Debug.yaml || printf -- "Debug:\n  developer_mode: false" > cmt.yaml.d/Debug.yaml ;\
	 test -f cmt.yaml.d/~Debug.yaml || printf -- "Debug:\n  value1: true" > cmt.yaml.d/~Debug.yaml ;\
	 test -f cmt.yaml.d/.Debug.yaml || printf -- "Debug:\n  value2: true" > cmt.yaml.d/.Debug.yaml ;\
	 test -f cmt.yaml.d/Debug || printf -- "Debug:\n  value3: true" > cmt.yaml.d/Debug ;\
	 test -f cmt.yaml.d/Empty.yml || touch cmt.yaml.d/Empty.yml ;\
	 test -f 01-wrong_permissions || touch 01-wrong_permissions ;\
	 test -L 02-symlink || ln -s 05-not_executable.sh 02-symlink ;\
	 test -d 03-wrong_dir_permissions || mkdir 03-wrong_dir_permissions ;\
	 test -L 04-dir_symlink || ln -s 03-wrong_dir_permissions 04-dir_symlink ;\
	 test -e 05-not_executable.sh || echo "#! /bin/sh\nprint -- \"This file should be executable\n\"" > 05-not_executable.sh ;\
	 test -e 06-executable.sh || echo "#! /bin/sh\nprint -- \"This file should NOT be executable\n\"" > 06-executable.sh ;\
	 test -L 07-dangling_symlink || ln -s this_destination_does_not_exist 07-dangling_symlink ;\
	 test -f 08-not_utf8.txt || /usr/bin/printf -- "\xc3\x28" > 08-not_utf8.txt ;\
	 test -f 09-this_is_not_valid.yaml || printf -- ": this is not valid yaml\nfoo\n" > 09-this_is_not_valid.yaml ;\
	 test -f 10-valid_yaml_for_load_all.yaml || printf -- "---\nvalid_yaml:\n  this_should_load_with_load_all: true\n---\nalso_valid_yaml:\n  everything_should_be_fine: true\n" > 10-valid_yaml_for_load_all.yaml ;\
	 test -f 11-valid_yaml_but_single.yaml || printf -- "valid_yaml:\n  but_only_when_using_load: true\n  this_wont_work_with_load_all: true\n" > 11-valid_yaml_but_single.yaml ;\
	 test -f 12-valid_yaml_followed_by_invalid_yaml.yaml || printf -- "---\nvalid_yaml:\n  this_should_load_with_load_all: true\n---\ninvalid_yaml:\n  : this is not valid yaml\n" > 12-valid_yaml_followed_by_invalid_yaml.yaml ;\
	 test -d 13-correct_directory || mkdir 13-correct_directory ;\
	 test -d 16-dir_no_permissions || mkdir 16-dir_no_permissions && chmod a= 16-dir_no_permissions ;\
	 test -f 03-wrong_dir_permissions/14-correct_file_in_wrong_permission_directory || touch 03-wrong_dir_permissions/14-correct_file_in_wrong_permission_directory ;\
	 test -L 15-symlink_directory || ln -s 13-correct_directory 15-symlink_directory ;\
	 test -f 13-correct_directory/16-correct_file_in_correct_permission_directory || touch 13-correct_directory/16-correct_file_in_correct_permission_directory ;\
	 test -e ssh || ln -s /usr/bin/ssh ssh ;\
	 test -f testfile.txt || printf -- "Random text\n" > testfile.txt ;\
	 test -f test_symlink || ln -s $$(pwd)/05-not_executable.sh test_symlink ;\
	 chmod a+x 06-executable.sh ;\
	 chmod o+w 03-wrong_dir_permissions ;\
	 chmod 0600 testfile.txt ;\
	 chmod o+w 01-wrong_permissions )

check_theme_use: setup_tests
	@printf -- "\n\nRunning check_theme_use to check that all verifiable uses of ThemeStr and ANSIThemeStr are valid\n\n"; \
	for theme in themes/*.yaml; do \
		printf -- "\nChecking against theme file $$theme:\n" ;\
		printf -- "---\n" ;\
		./tests/check_theme_use.py $$theme $(python_executables_py) clustermanagementtoolkit/*.py ;\
	done

# This target removes all files that are built from templates, to ensure they don't get committed to the repo by mistake.
clean_templates:
	@for path in views/templates/*.j2; do \
		file=$$(basename $$path)	;\
		rm -f views/$${file%.j2}	;\
	done

build_templates:
	./build.py views/templates views/variables views

clean_index:
	@rm -f views/__resource_type_index.yaml

build_index:
	./generate_resource_type_index.py views views/__resource_type_index.yaml

build: build_templates build_index

# This rule is used when making a system-wide install
INSTALL := install --mode=755
INSTALL_DATA := install --mode=644
INSTALL_DIRECTORY := install -d
BASH_COMPLETION_DIR := /usr/share/bash-completion/completions
CMT_CONFIG_DIR := /etc/cmt
CMT_CONFIGLET_DIR := $(CMT_CONFIG_DIR)/cmt.yaml.d
CMT_DATA_DIR := /usr/share/cluster-management-toolkit
CMT_VIEWS_DIR := $(CMT_DATA_DIR)/views
DIST_PACKAGE_DIR := /usr/lib/python3/dist-packages
BINDIR := /usr/bin
COMPLETION_FILES := bash-completion/cmt bash-completion/cmtadm bash-completion/cmtinv bash-completion/cmu

.PHONY: bin
bin:
	@mkdir -p bin &&\
	for file in $(python_executables); do \
		devtools/mangle_source.py $${file}.py > bin/$${file} && chmod a+x bin/$${file} ;\
	done

install: bin
	@$(INSTALL_DIRECTORY) $(DESTDIR)$(BASH_COMPLETION_DIR) &&\
	$(INSTALL_DIRECTORY) $(DESTDIR)$(CMT_CONFIGLET_DIR) &&\
	$(INSTALL_DIRECTORY) $(DESTDIR)$(CMT_DATA_DIR) &&\
	$(INSTALL_DIRECTORY) $(DESTDIR)$(CMT_VIEWS_DIR) &&\
	$(INSTALL_DIRECTORY) $(DESTDIR)$(DIST_PACKAGE_DIR) &&\
	$(INSTALL_DIRECTORY) $(DESTDIR)$(BINDIR) &&\
	$(INSTALL_DATA) cmt.yaml $(DESTDIR)$(CMT_CONFIG_DIR) &&\
	$(INSTALL_DATA) $(COMPLETION_FILES) $(DESTDIR)$(BASH_COMPLETION_DIR) &&\
	$(INSTALL) bin/cmt $(DESTDIR)$(BINDIR) &&\
	$(INSTALL) bin/cmtadm $(DESTDIR)$(BINDIR) &&\
	$(INSTALL) bin/cmtinv $(DESTDIR)$(BINDIR) &&\
	$(INSTALL) bin/cmu $(DESTDIR)$(BINDIR) &&\
	tar cf - --exclude-ignore=$$(pwd)/.gitignore clustermanagementtoolkit | (cd $(DESTDIR)$(DIST_PACKAGE_DIR); tar xf -) &&\
	tar cf - --exclude-ignore=$$(pwd)/.gitignore parsers playbooks sources themes | (cd $(DESTDIR)$(CMT_DATA_DIR); tar xf -) &&\
	cp views/*.yaml $(DESTDIR)$(CMT_VIEWS_DIR) || printf -- "Installation failed.\n"
