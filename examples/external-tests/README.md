# External Tests Example

This directory demonstrates how external projects (like osbuild) would use `cloud-image-val` as a library to write tests for their cloud image definitions.

## Concept

Instead of maintaining tests inside `cloud-image-val`, image maintainers can:

1. **Keep tests in their own repository** alongside image definitions
2. **Use cloud-image-val as a versioned Python library** (like any other dependency)
3. **Make atomic commits** when both image definition and tests change
4. **Pin to specific cloud-image-val versions** for stability

## Repository Structure (Example for osbuild)

```
osbuild-repo/
├── image-definitions/
│   ├── rhel-9-base.json
│   ├── rhel-9-sap.json
│   └── fedora-40.json
├── tests/
│   ├── requirements.txt          # pins cloud-image-val version
│   ├── conftest.py               # pytest configuration
│   ├── test_rhel9_base.py        # tests for rhel-9-base.json
│   ├── test_rhel9_sap.py         # tests for rhel-9-sap.json
│   └── test_fedora40.py          # tests for fedora-40.json
├── .github/workflows/
│   └── validate-images.yml       # CI runs tests on built images
└── README.md
```

## Setup

### Install cloud-image-val library

```bash
cd tests/
pip install -r requirements.txt
```

The `requirements.txt` pins `cloud-image-val` to a version range:

```
cloud-image-val>=1.0.0,<2.0.0
```

### Run tests

```bash
# Run locally against a test instance
pytest --hosts=ssh://user@hostname --connection=paramiko --ssh-config=~/.ssh/config

# Run with cloud-image-val's suite runner (for parallel execution)
python -m cloud_image_val.runner --cloud aws --instances instances.json
```

## Writing Tests

### Import from cloud-image-val

```python
from cloud_image_val import (
    run_on,
    exclude_on,
    assert_file_empty,
    assert_package_installed,
    get_host_info,
)

@run_on(['rhel>=9'])
def test_something(host):
    assert_package_installed(host, 'cloud-init')
```

### Available decorators

- `@run_on(['all'])` - Run on all distros
- `@run_on(['rhel>=9', 'fedora'])` - Run on RHEL 9+ and Fedora
- `@exclude_on(['rhel8'])` - Exclude specific versions
- `@wait(30)` - Wait 30 seconds before running test

### Available assertions

```python
# File checks
assert_file_exists(host, '/etc/cloud/cloud.cfg')
assert_file_not_exists(host, '/root/.bash_history')
assert_file_empty(host, '/var/log/audit/audit.log')
assert_file_contains(host, '/etc/fstab', 'xfs')

# Package checks
assert_package_installed(host, 'cloud-init')
assert_package_not_installed(host, 'telnet-server')

# Service checks
assert_service_running(host, 'sshd')
assert_service_enabled(host, 'cloud-init')

# Command checks
assert_command_succeeds(host, 'systemctl is-active sshd')
assert_command_fails(host, 'systemctl is-active bad.service')

# Security checks
assert_no_avc_denials(host)
```

### Host information

```python
from cloud_image_val import get_host_info

def test_arch_specific(host):
    info = get_host_info(host)
    
    if info.arch == 'aarch64':
        assert_file_contains(host, '/proc/cmdline', 'console=ttyAMA0')
    else:
        assert_file_contains(host, '/proc/cmdline', 'console=ttyS0')
```

## Atomic Image + Test Changes

When you change an image definition in a way that affects tests:

```bash
# In osbuild repo
git checkout -b add-custom-config

# 1. Modify image definition
vim image-definitions/rhel-9-base.json
# Add: install package 'custom-tool'

# 2. Update/add test in same commit
vim tests/test_rhel9_base.py
# Add: assert_package_installed(host, 'custom-tool')

# 3. Commit atomically
git add image-definitions/rhel-9-base.json tests/test_rhel9_base.py
git commit -m "Add custom-tool package to RHEL 9 base image"

# 4. CI builds image and runs tests - both changes are in sync
```

## Benefits

### ✅ Tests controlled by image maintainers
No need to open PRs in cloud-image-val repo for every image change.

### ✅ Atomic commits
Image definition + test changes in single commit = always in sync.

### ✅ Version pinning
Pin to specific cloud-image-val versions for stability.

### ✅ Independent development
- cloud-image-val can evolve its internals without breaking your tests
- Your tests use the stable API (decorators, assertions, host info)
- Semantic versioning makes breaking changes explicit

### ✅ Standard dependency management
Just like any Python library - use pip, virtual environments, etc.

## Versioning

### Semantic Versioning

- `1.x.x` - Stable API, backward compatible changes
- `2.0.0` - Major version with potential breaking changes

### When to update cloud-image-val version

**Patch updates (1.0.x → 1.0.y)**: Safe to update anytime
- Bug fixes
- Internal improvements
- No API changes

**Minor updates (1.x.0 → 1.y.0)**: Review changelog, usually safe
- New features added
- API additions (new assertions, decorators)
- Backward compatible

**Major updates (1.x.x → 2.0.0)**: Review migration guide
- Breaking API changes
- Requires test updates
- Plan migration

### Pin Strategy

```txt
# Conservative: exact version
cloud-image-val==1.0.0

# Recommended: minor version range
cloud-image-val>=1.0.0,<2.0.0

# Flexible: major version range (get latest features)
cloud-image-val>=1.0.0,<2.0.0
```

## CI Integration

### Example GitHub Actions workflow

```yaml
name: Validate Image Definitions

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          cd tests
          pip install -r requirements.txt
      
      - name: Build test image
        run: |
          # Build image from definition
          osbuild-composer build image-definitions/rhel-9-base.json
      
      - name: Deploy test instance
        run: |
          # Deploy to cloud for testing
          ./deploy-test-instance.sh
      
      - name: Run validation tests
        run: |
          cd tests
          pytest test_rhel9_base.py \
            --hosts=ssh://cloud-user@$TEST_INSTANCE_IP \
            --connection=paramiko \
            --junit-xml=results.xml
      
      - name: Publish test results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: tests/results.xml
```

## Migration from Embedded Tests

If you currently have tests in cloud-image-val and want to move them:

1. Create `tests/` directory in your image definition repo
2. Copy relevant test files
3. Update imports to use `cloud_image_val` API
4. Add `requirements.txt` pinning cloud-image-val version
5. Update CI to run tests from your repo
6. Remove tests from cloud-image-val (or mark as examples)

## Support

- **API Documentation**: See cloud-image-val package docstrings
- **Issues**: Open issues in your repo for image-specific tests
- **cloud-image-val issues**: https://github.com/osbuild/cloud-image-val/issues
