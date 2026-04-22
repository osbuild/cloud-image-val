"""
Advanced examples showing how to use cloud-image-val library features.

This demonstrates more complex test scenarios and patterns.
"""

import pytest
from packaging import version
from cloud_image_val import (
    run_on,
    exclude_on,
    wait,
    assert_file_exists,
    assert_file_contains,
    assert_command_succeeds,
    assert_service_running,
    get_host_info,
)


class TestKernelConfiguration:
    """Group related tests in a class for organization."""

    @run_on(['all'])
    def test_kernel_modules_loaded(self, host):
        """Verify required kernel modules are loaded."""
        required_modules = ['xfs', 'ext4']

        with host.sudo():
            result = host.run('lsmod')

        for module in required_modules:
            assert module in result.stdout, f"Module {module} not loaded"

    @run_on(['rhel>=9'])
    @exclude_on(['rhel10'])  # Different behavior in RHEL 10
    def test_kernel_params_rhel9(self, host):
        """Test RHEL 9 specific kernel parameters."""
        assert_file_contains(host, '/proc/cmdline', 'net.ifnames=0')


class TestCloudInit:
    """Cloud-init specific tests."""

    @run_on(['all'])
    def test_cloud_init_config_exists(self, host):
        """Verify cloud-init configuration files are present."""
        config_files = [
            '/etc/cloud/cloud.cfg',
            '/etc/cloud/cloud.cfg.d/10_cloud_image.cfg',
        ]

        for config_file in config_files:
            assert_file_exists(host, config_file)

    @run_on(['all'])
    @wait(60)  # Wait for cloud-init to complete
    def test_cloud_init_completed(self, host):
        """Verify cloud-init has completed successfully."""
        result = assert_command_succeeds(
            host,
            'cloud-init status --wait',
            message="cloud-init did not complete successfully"
        )
        assert 'done' in result.stdout.lower()


@run_on(['all'])
def test_with_host_info(host):
    """Example using host information for conditional logic."""
    info = get_host_info(host)

    # Different expectations based on distro
    if info.distro == 'rhel':
        if info.version_parsed >= version.parse('9.0'):
            # RHEL 9+ uses NetworkManager only
            assert_service_running(host, 'NetworkManager')
        else:
            # RHEL 8 might have network-scripts
            pass

    # Architecture-specific checks
    if info.arch == 'aarch64':
        assert_file_contains(host, '/proc/cpuinfo', 'ARM')
    elif info.arch == 'x86_64':
        assert_file_contains(host, '/proc/cpuinfo', r'Intel\|AMD')


@run_on(['rhel>=9'])
@pytest.mark.parametrize('user', ['root', 'cloud-user'])
def test_user_bash_history_empty(host, user):
    """
    Parametrized test checking bash history for multiple users.

    This demonstrates using pytest's parametrize with cloud-image-val.
    """
    from cloud_image_val import assert_file_empty

    file_path = f'/home/{user}/.bash_history' if user != 'root' else '/root/.bash_history'
    assert_file_empty(host, file_path)


@run_on(['all'])
def test_with_custom_fixture(host, expected_packages):
    """
    Example using custom fixture from conftest.py.

    The expected_packages fixture is defined in conftest.py
    and provides distro-specific package lists.
    """
    from cloud_image_val import assert_package_installed

    for package in expected_packages:
        assert_package_installed(host, package)


@run_on(['rhel'])
def test_with_raw_testinfra(host):
    """
    Example showing you can still use testinfra directly.

    cloud-image-val doesn't replace testinfra, it wraps it.
    You can use raw testinfra commands when needed.
    """
    # Use cloud-image-val helper
    from cloud_image_val import get_host_info
    info = get_host_info(host)

    # Use raw testinfra
    with host.sudo():
        result = host.run('rpm -qa | grep rhui')
        assert result.succeeded

    # Mix both approaches
    if 'sap' in result.stdout:
        # Use cloud-image-val assertion
        from cloud_image_val import assert_package_installed
        assert_package_installed(host, 'sap-hana')


class TestSecurityHardening:
    """Security-focused tests."""

    @run_on(['all'])
    def test_no_default_passwords(self, host):
        """Verify no default/weak passwords are set."""
        with host.sudo():
            # Check shadow file for accounts with no password
            result = host.run("awk -F: '($2 == \"\" ) { print $1 }' /etc/shadow")
            assert not result.stdout.strip(), "Found accounts with no password"

    @run_on(['rhel'])
    def test_required_security_packages(self, host):
        """Verify security packages are installed."""
        from cloud_image_val import assert_package_installed

        security_packages = [
            'selinux-policy-targeted',
            'policycoreutils',
        ]

        for package in security_packages:
            assert_package_installed(host, package)


@run_on(['all'])
def test_demonstrating_failure_messages(host):
    """
    Example showing custom error messages for better debugging.
    """
    from cloud_image_val import assert_file_contains

    # Custom message helps identify what went wrong
    assert_file_contains(
        host,
        '/etc/fstab',
        'xfs',
        message="Expected XFS filesystem in fstab for root volume"
    )


@run_on(['rhel>=9'])
def test_complex_validation(host):
    """
    Example of more complex validation logic.

    This shows how you can combine multiple assertions and
    conditionals for sophisticated test scenarios.
    """
    from cloud_image_val import (
        assert_file_exists,
        assert_command_succeeds,
        get_host_info,
    )

    info = get_host_info(host)

    # Multi-step validation
    assert_file_exists(host, '/etc/cloud/cloud.cfg')

    # Run command and check output
    result = assert_command_succeeds(host, 'cloud-init query -a')

    # Parse JSON output (if applicable)
    import json
    try:
        cloud_init_data = json.loads(result.stdout)
        assert 'instance_id' in cloud_init_data, "cloud-init data missing instance_id"
    except json.JSONDecodeError:
        pytest.fail("cloud-init query did not return valid JSON")

    # Conditional checks based on host info
    if info.arch == 'x86_64':
        result = assert_command_succeeds(host, 'cat /proc/cpuinfo')
        assert 'vmx' in result.stdout or 'svm' in result.stdout, \
            "Expected virtualization support on x86_64"
