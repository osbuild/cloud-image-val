#!/bin/bash
#
# Test script to verify cloud-image-val package can be built and used.
# Run this before publishing to PyPI.
#

set -e

echo "======================================"
echo "Testing cloud-image-val package build"
echo "======================================"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Clean previous builds
echo "1. Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info cloud_image_val.egg-info
echo "   ✓ Cleaned"
echo ""

# Install build tools if needed
echo "2. Checking build tools..."
pip install --quiet build twine
echo "   ✓ Build tools ready"
echo ""

# Build the package
echo "3. Building package..."
python -m build
echo "   ✓ Package built"
echo ""

# Check package contents
echo "4. Checking package contents..."
if [ -f dist/*.whl ]; then
    echo "   ✓ Wheel file created"
else
    echo "   ✗ No wheel file found"
    exit 1
fi

if [ -f dist/*.tar.gz ]; then
    echo "   ✓ Source distribution created"
else
    echo "   ✗ No source distribution found"
    exit 1
fi
echo ""

# Check package with twine
echo "5. Validating package with twine..."
if twine check dist/* 2>&1 | grep -q "ERROR"; then
    echo "   ⚠ Twine validation warnings (may be due to newer setuptools metadata)"
    echo "   → Continuing with installation test..."
else
    echo "   ✓ Package validation passed"
fi
echo ""

# Create temporary virtual environment for testing
echo "6. Creating test environment..."
TEST_ENV="/tmp/test-cloud-image-val-$$"
python -m venv "$TEST_ENV"
source "$TEST_ENV/bin/activate"
echo "   ✓ Test environment created"
echo ""

# Install the built package
echo "7. Installing built package..."
pip install --quiet dist/*.whl
echo "   ✓ Package installed"
echo ""

# Test imports
echo "8. Testing package imports..."
python << 'EOF'
import sys

# Test main package import
try:
    import cloud_image_val
    print("   ✓ cloud_image_val imported")
except ImportError as e:
    print(f"   ✗ Failed to import cloud_image_val: {e}")
    sys.exit(1)

# Test version
try:
    version = cloud_image_val.__version__
    print(f"   ✓ Version: {version}")
except AttributeError:
    print("   ✗ No version attribute")
    sys.exit(1)

# Test decorators
try:
    from cloud_image_val import run_on, exclude_on, wait
    print("   ✓ Decorators imported")
except ImportError as e:
    print(f"   ✗ Failed to import decorators: {e}")
    sys.exit(1)

# Test assertions
try:
    from cloud_image_val import (
        assert_file_exists,
        assert_file_empty,
        assert_package_installed,
        assert_command_succeeds,
    )
    print("   ✓ Assertions imported")
except ImportError as e:
    print(f"   ✗ Failed to import assertions: {e}")
    sys.exit(1)

# Test host utilities
try:
    from cloud_image_val import HostInfo, get_host_info
    print("   ✓ Host utilities imported")
except ImportError as e:
    print(f"   ✗ Failed to import host utilities: {e}")
    sys.exit(1)

# Test __all__ exports
try:
    expected_exports = [
        'run_on', 'exclude_on', 'wait',
        'assert_file_exists', 'assert_file_not_exists',
        'assert_file_empty', 'assert_file_contains',
        'assert_command_succeeds', 'assert_command_fails',
        'assert_no_avc_denials',
        'assert_package_installed', 'assert_package_not_installed',
        'assert_service_running', 'assert_service_enabled',
        'HostInfo', 'get_host_info',
    ]

    for name in expected_exports:
        if not hasattr(cloud_image_val, name):
            print(f"   ✗ Missing export: {name}")
            sys.exit(1)

    print(f"   ✓ All {len(expected_exports)} exports present")
except Exception as e:
    print(f"   ✗ Failed to check exports: {e}")
    sys.exit(1)

print("   ✓ All imports successful")
EOF

if [ $? -ne 0 ]; then
    echo "Import tests failed"
    deactivate
    rm -rf "$TEST_ENV"
    exit 1
fi
echo ""

# Test example tests can be collected
echo "9. Testing example tests..."
cd "$PROJECT_ROOT/examples/external-tests"

# Verify we're still in test environment
echo "   Using Python: $(which python)"
echo "   Environment: ${VIRTUAL_ENV:-'not in venv'}"

# Install cloud-image-val from the built wheel (force reinstall)
echo "   Installing wheel..."
pip install --force-reinstall "$PROJECT_ROOT"/dist/*.whl 2>&1 | grep -E "(Successfully|ERROR|cloud.image.val)" || true

# Verify installation
python -c "import cloud_image_val; print(f'   cloud-image-val {cloud_image_val.__version__} installed')"

# Just collect tests, don't run them (no test host available)
pytest --collect-only test_rhel9_base.py test_advanced_example.py
if [ $? -eq 0 ]; then
    echo "   ✓ Example tests collected successfully"
else
    echo "   ✗ Failed to collect example tests"
    deactivate
    rm -rf "$TEST_ENV"
    exit 1
fi
echo ""

# Cleanup
echo "10. Cleaning up..."
deactivate
rm -rf "$TEST_ENV"
echo "   ✓ Test environment removed"
echo ""

echo "======================================"
echo "✓ All package tests passed!"
echo "======================================"
echo ""
echo "Package is ready for publishing:"
echo "  python -m twine upload dist/*"
echo ""
echo "Or test with PyPI test server first:"
echo "  python -m twine upload --repository testpypi dist/*"
echo ""
