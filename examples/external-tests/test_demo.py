"""
Simple demo tests that will pass on any Linux system.
Use these to verify the library is working.
"""

from cloud_image_val import (
    run_on,
    assert_file_exists,
    assert_command_succeeds,
    get_host_info,
)


@run_on(['all'])
def test_basic_system_files(host):
    """Verify basic system files exist."""
    assert_file_exists(host, '/etc/passwd')
    assert_file_exists(host, '/etc/hostname')
    assert_file_exists(host, '/proc/cpuinfo')


@run_on(['all'])
def test_basic_commands(host):
    """Verify basic commands work."""
    assert_command_succeeds(host, 'whoami')
    assert_command_succeeds(host, 'uname -a')
    assert_command_succeeds(host, 'pwd')


@run_on(['all'])
def test_host_info(host):
    """Test host information extraction."""
    info = get_host_info(host)

    # Just verify we got information
    assert info.distro, "Should have distro"
    assert info.version, "Should have version"
    assert info.arch, "Should have architecture"

    print(f"\nHost Info:")
    print(f"  Distro: {info.distro}")
    print(f"  Version: {info.version}")
    print(f"  Arch: {info.arch}")
    print(f"  Distro-Version: {info.distro_version}")
