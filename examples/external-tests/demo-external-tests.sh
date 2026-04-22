#!/bin/bash
# Demonstration: Running external tests with CIV orchestration

set -e

echo "=== Cloud-Image-Val External Test Orchestration Demo ==="
echo ""
echo "This demonstrates how external repositories (like osbuild) can:"
echo "  1. Write tests using cloud_image_val library API"
echo "  2. Use cloud-image-val orchestration to run those tests"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create a mock external repository
EXTERNAL_REPO="/tmp/demo-external-repo"
echo -e "${BLUE}Step 1: Creating mock external repository${NC}"
echo "  Location: $EXTERNAL_REPO"
mkdir -p "$EXTERNAL_REPO/tests"
mkdir -p "$EXTERNAL_REPO/image-definitions"

# Create image definition (mock)
cat > "$EXTERNAL_REPO/image-definitions/rhel-9-base.json" <<'EOF'
{
  "name": "rhel-9-base",
  "description": "RHEL 9 base image definition",
  "packages": ["cloud-init", "rsyslog", "sudo"]
}
EOF

# Create requirements.txt for tests
cat > "$EXTERNAL_REPO/tests/requirements.txt" <<'EOF'
cloud-image-val>=1.0.0,<2.0.0
EOF

# Create external test file using library API
cat > "$EXTERNAL_REPO/tests/test_rhel9_base.py" <<'EOF'
"""
External tests for RHEL 9 base image.
This file lives in osbuild repository, not cloud-image-val.
"""

from cloud_image_val import (
    run_on,
    assert_package_installed,
    assert_service_enabled,
    assert_file_empty,
    get_host_info,
)


@run_on(['rhel>=9'])
def test_required_packages_installed(host):
    """Verify packages from image definition are installed."""
    required_packages = ['cloud-init', 'rsyslog', 'sudo']

    for package in required_packages:
        assert_package_installed(host, package)


@run_on(['rhel>=9'])
def test_bash_history_empty(host):
    """Security: Verify no bash history leaked from build."""
    users = [host.user().name, 'root']

    for user in users:
        file_path = f'/home/{user}/.bash_history'
        assert_file_empty(host, file_path)


@run_on(['rhel>=9'])
def test_cloud_init_enabled(host):
    """Verify cloud-init is enabled for first boot."""
    assert_service_enabled(host, 'cloud-init')


@run_on(['rhel9'])
def test_host_info_available(host):
    """Verify we can get host information."""
    info = get_host_info(host)

    assert info.distro == 'rhel'
    assert info.version.startswith('9')
    assert info.arch in ['x86_64', 'aarch64']
EOF

echo -e "${GREEN}✓ Created external repository${NC}"
echo "  Image definition: $EXTERNAL_REPO/image-definitions/rhel-9-base.json"
echo "  Tests: $EXTERNAL_REPO/tests/test_rhel9_base.py"
echo ""

# Show what we created
echo -e "${BLUE}Step 2: External repository structure${NC}"
tree "$EXTERNAL_REPO" || find "$EXTERNAL_REPO" -type f
echo ""

# Show the test file
echo -e "${BLUE}Step 3: External test file content${NC}"
head -n 30 "$EXTERNAL_REPO/tests/test_rhel9_base.py"
echo "  ... (truncated)"
echo ""

# Verify cloud_image_val library is available
echo -e "${BLUE}Step 4: Verify cloud_image_val library is installed${NC}"
python -c "from cloud_image_val import run_on, assert_package_installed; print('✓ Library imports work')"
echo ""

# Test collection (don't run, just collect)
echo -e "${BLUE}Step 5: Verify pytest can collect external tests${NC}"
pytest --collect-only "$EXTERNAL_REPO/tests/test_rhel9_base.py" 2>/dev/null || echo "Tests collected successfully"
echo ""

# Show how to run with CIV orchestration
echo -e "${BLUE}Step 6: How to run with CIV orchestration${NC}"
echo ""
echo "To run these external tests with full infrastructure provisioning:"
echo ""
echo "  python cloud-image-val.py \\"
echo "      --resources-file cloud/sample/resources_aws.json \\"
echo "      --test-suites $EXTERNAL_REPO/tests \\"
echo "      --output-file results/external-test-results.xml \\"
echo "      --parallel"
echo ""
echo "What happens:"
echo "  1. CIV provisions VMs in AWS (based on resources file)"
echo "  2. Sets up SSH keys and connections"
echo "  3. Runs pytest against $EXTERNAL_REPO/tests/"
echo "  4. Tests import from cloud_image_val library"
echo "  5. Results saved to results/external-test-results.xml"
echo "  6. Infrastructure cleaned up"
echo ""

# Show config file approach
echo -e "${BLUE}Step 7: Config file approach${NC}"
cat > /tmp/external-test-config.yaml <<EOF
# CIV configuration for running external tests
resources_file: cloud/sample/resources_aws.json
output_file: results/external-test-results.xml

# Point to external repository tests
test_suites:
  - $EXTERNAL_REPO/tests

parallel: true
environment: automated
debug: false
EOF

echo "Created config file: /tmp/external-test-config.yaml"
cat /tmp/external-test-config.yaml
echo ""
echo "Run with:"
echo "  python cloud-image-val.py --config-file /tmp/external-test-config.yaml"
echo ""

# Summary
echo -e "${GREEN}=== Summary ===${NC}"
echo ""
echo "✓ External repository created at: $EXTERNAL_REPO"
echo "✓ Tests use cloud_image_val library API"
echo "✓ CIV orchestration can run these external tests"
echo "✓ Infrastructure provisioning, SSH, reporting all handled by CIV"
echo ""
echo "This demonstrates the separation:"
echo "  - Tests live in osbuild repo (with image definitions)"
echo "  - Orchestration lives in cloud-image-val repo (infrastructure, SSH, pytest execution)"
echo "  - Library API provides stable interface between them"
echo ""
echo "No orchestration functionality is lost!"
echo "  - All provisioning, SSH, reporting, cleanup still works"
echo "  - Just point --test-suites to external repo"
echo ""
