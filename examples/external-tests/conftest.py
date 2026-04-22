"""
Pytest configuration for external tests using cloud-image-val library.

This conftest.py is used by external test repositories (like osbuild's)
to configure pytest for their image validation tests.

The cloud-image-val library handles the marker checking automatically
via its own conftest.py when imported as a dependency.
"""

import pytest

# The cloud-image-val library provides the necessary pytest configuration
# through its own conftest.py and fixtures when installed as a package.

# You can add project-specific fixtures here:


@pytest.fixture(scope="session")
def image_definition_version():
    """
    Example fixture providing image definition metadata.

    This could read from a version file in the osbuild repo.
    """
    return "2024.1"


@pytest.fixture
def expected_packages(host):
    """
    Example fixture that returns expected packages based on host distro.

    This demonstrates how external tests can define their own helpers
    while using cloud-image-val's core functionality.
    """
    from cloud_image_val import get_host_info

    info = get_host_info(host)

    base_packages = ['cloud-init', 'rsyslog', 'sudo']

    if info.distro == 'rhel':
        if info.version_parsed.major >= 9:
            return base_packages + ['NetworkManager']
        else:
            return base_packages + ['network-scripts']

    return base_packages
