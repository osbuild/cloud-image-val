"""
Example external tests for RHEL 9 base cloud images.

This file demonstrates how the osbuild team would write tests
in their own repository using cloud-image-val as a library.

These tests live alongside image definitions, allowing atomic commits
when both image and test change together.
"""

import pytest
from cloud_image_val import (
    run_on,
    exclude_on,
    assert_file_empty,
    assert_file_contains,
    assert_package_installed,
    assert_service_running,
    assert_service_enabled,
    assert_no_avc_denials,
    get_host_info,
)


@run_on(['rhel>=9'])
def test_bash_history_is_empty(host):
    """
    Verify that bash history files are empty in fresh images.

    This is a security requirement - no build artifacts should leak.
    """
    users = [host.user().name, 'root']

    for user in users:
        file_path = f'/home/{user}/.bash_history'
        assert_file_empty(host, file_path)


@run_on(['rhel>=9'])
def test_cloud_init_installed_and_enabled(host):
    """
    Verify cloud-init is properly configured for cloud images.
    """
    assert_package_installed(host, 'cloud-init')
    assert_service_enabled(host, 'cloud-init')


@run_on(['rhel>=9'])
def test_selinux_no_denials(host):
    """
    Verify no SELinux AVC denials exist in the image.
    """
    assert_no_avc_denials(host)


@run_on(['rhel>=9'])
def test_kernel_command_line(host):
    """
    Verify required kernel parameters are present.
    """
    info = get_host_info(host)

    # Check console based on architecture
    if info.arch == 'aarch64':
        assert_file_contains(host, '/proc/cmdline', 'console=ttyAMA0')
    else:
        assert_file_contains(host, '/proc/cmdline', 'console=ttyS0')

    # Check other required parameters
    assert_file_contains(host, '/proc/cmdline', 'net.ifnames=0')


@run_on(['rhel>=9'])
def test_required_packages_installed(host):
    """
    Verify all required packages for cloud images are installed.
    """
    required_packages = [
        'cloud-init',
        'rsyslog',
        'sudo',
        'openssh-server',
    ]

    for package in required_packages:
        assert_package_installed(host, package)


@run_on(['rhel>=9'])
@exclude_on(['rhel10'])  # Different handling in RHEL 10
def test_network_scripts_not_present(host):
    """
    Verify legacy network scripts are not present (NetworkManager only).
    """
    # This test might fail if image definition changes to include network scripts
    # When osbuild changes the definition, they update this test in the same commit
    from cloud_image_val import assert_file_not_exists
    assert_file_not_exists(host, '/etc/sysconfig/network-scripts/ifcfg-eth0')


# This demonstrates a test that's specific to image definition changes
@run_on(['rhel9'])
def test_custom_osbuild_marker_file(host):
    """
    Example: Test for a custom file added by osbuild image definition.

    If the osbuild team adds a marker file in their image definition,
    they add this test in the same commit to verify it's present.
    """
    # This would fail in cloud-image-val's own tests, but pass in osbuild's
    # when they build images with their definitions

    # Uncomment when the image definition adds this file:
    # assert_file_contains(host, '/etc/osbuild-image-version', '2024.1')
    pass
