# Test Spike: YAML-Based Test Suite Executor

This spike implements a decoupled test executor that reads tests from YAML format instead of pytest, demonstrating the feasibility of the refactoring.

## Architecture

spike/
  test_executor/           # Core executor engine
    __init__.py
    schema.py           # YAML schema and parser
    executor.py         # Test execution engine
    cli.py              # CLI entry point
    spike_tests/
    *yaml                 # Tests converted to Yaml

## Usage

### Local Execution

```bash
python3 -m spike.test_executor.cli \
  --test-file spike/spike_tests/test_bash_history_empty.yaml \
  --verbose
```

### Remote Execution (SSH)

```bash
python3 -m spike.test_executor.cli \
  --test-file spike/spike_tests/test_bash_history_empty.yaml \
  --host myhost.example.com \
  --user cloud-user \
  --ssh-config ~/.ssh/config \
  --verbose
```

### With Manual Host Info Override

```bash
python3 -m spike.test_executor.cli \
  --test-file spike/spike_tests/test_bash_history_empty.yaml \
  --distro rhel \
  --version 9.3 \
  --arch x86_64 \
  --verbose
```

### Save Results as JSON

```bash
python3 -m spike.test_executor.cli \
  --test-file spike/spike_tests/test_bash_history_empty.yaml \
  --output results.json \
  --verbose
```

## YAML Test Format

### Example: `test_bash_history_empty.yaml`

```yaml
test_id: "bash_history_empty"
name: "Bash History Is Empty"
description: "Validates that bash history files are empty"
tags:
  - generic
  - basic

conditions:
  run_on: 
    - all        # Run on all distros
  exclude_on: []
  wait_seconds: 0

steps:
  - action: run_command
    name: "Get current user"
    command: "whoami"
    store_as: "current_user"
  
  - action: check_file_content
    name: "Check current user bash history"
    path: "/home/${current_user}/.bash_history"
    operator: empty
```

### Step Actions

Implemented actions:
- **run_command**: Execute shell command
- **check_file**: Check file existence
- **check_file_content**: Validate file content (empty, not_empty, contains)
- **assert_command_exit_code**: Verify command exit code

TODO: EXTEND FOR FULL FUNCTIONALITY

### Conditions

- **run_on**: List of distros/versions where test runs
  - Values: `['rhel', 'rhel9', 'rhel8', 'fedora', 'all']`
  - Relational: `['rhel>=9', 'rhel<10']`
  
- **exclude_on**: Distros/versions where test is skipped

- **wait_seconds**: Delay before running test

## Advantages Over pytest

- Decoupled: Tests are independent of pytest framework
- Portable: YAML tests can be executed on remote hosts directly, no python needed
- Simple: Easy to understand, no Python knowledge required to write tests
- Extensible: New step actions can be added without framework changes
- Tests can be maintained outside of the cloud-image-val project

## Disadvantages Over pytest

- Less expressive: Cannot use Python's full expressiveness for complex test logic, conditionals, or loops
- Limited ecosystem: No access to Python libraries, pytest plugins, or fixtures ecosystem
- More verbose: Simple operations may require more YAML compared to equivalent Python code
- Debugging challenges: Stack traces and debugging tools are less mature than pytest's debugging capabilities
- No IDE support: Limited autocomplete, syntax highlighting, and validation compared to Python in IDEs
- Learning curve: Teams must learn new YAML schema and action types instead of using familiar pytest patterns
- Limited control flow: No native support for loops, complex conditionals, or dynamic test generation within steps
- Action dependency: Every new test requirement may need a new action type implemented in the executor
- Parametrization limitations: Less flexible than pytest's parametrize decorator for running variations of tests
- No native mocking: Cannot easily mock functions or modules like with pytest fixtures and monkeypatch

# YAML Test Schema Documentation
## Root Level Fields
- test_id: str (required) - Unique identifier for the test
- name: str (required) - Human-readable test name
- description: str (required) - Test description
- conditions: object (required) - Execution conditions (test-level)
- steps: list (required) - Test execution steps
- tags: list (optional) - Tags for categorization

## Conditions Object (test-level and per-step)
- run_on: list (optional, default: ['all'])
  Values: ['rhel', 'rhel8', 'rhel9', 'fedora', 'all', 'centos']
  Relational: ['rhel>=9', 'rhel<10', 'rhel>=9.6']
- exclude_on: list (optional) - Same format as run_on
- wait_seconds: int (optional, default: 0) - Delay before running test (test-level only)

## Per-step Conditions
Any step may carry an optional `conditions` key with `run_on` / `exclude_on`.
When the host does not match, the step is skipped (not failed).

## Steps — Action Types

### assert_command_exit_code
  command: str - Shell command to execute
  expected: int - Expected exit code (usually 0)

### run_command
  command: str - Shell command to execute (success = exit 0)
  store_as: str (optional) - Store stdout in a variable

### check_file
  path: str - File path
  operator: 'exists' | 'not_exists' | 'linked_to' | 'mode'
  expected: str - For 'linked_to': resolved path; for 'mode': octal string e.g. "640"

### check_file_content
  path: str - File path
  operator: 'empty' | 'not_empty' | 'contains' | 'not_contains'
  expected: str - Required for 'contains' / 'not_contains'

### check_command_output
  command: str - Command whose stdout is asserted
  operator: 'equals' | 'contains' | 'not_contains' | 'empty' | 'not_empty'
  expected: str - Expected value

### check_service
  service: str - Systemd service name
  operator: 'is_running' | 'is_active' | 'is_enabled' | 'not_running' | 'not_enabled'

### check_package
  package: str - RPM package name
  operator: 'is_installed' | 'not_installed'

### check_user
  user: str - OS username
  operator: 'exists' | 'not_exists'

### compare_file_with_local
  path: str - Remote file path
  params:
    local_path: str - Path to local reference file (relative to CWD or absolute)