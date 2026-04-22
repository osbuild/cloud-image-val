"""
Test assertion helpers for common cloud image validation checks.

These functions provide a stable, high-level API for common test assertions.
"""


def assert_file_exists(host, path, message=None):
    """
    Assert that a file exists on the host.

    Args:
        host: testinfra host fixture
        path: File path to check
        message: Optional custom error message

    Example:
        assert_file_exists(host, '/etc/cloud/cloud.cfg')
    """
    file = host.file(path)
    error_msg = message or f"File {path} does not exist"
    assert file.exists, error_msg


def assert_file_not_exists(host, path, message=None):
    """
    Assert that a file does not exist on the host.

    Args:
        host: testinfra host fixture
        path: File path to check
        message: Optional custom error message

    Example:
        assert_file_not_exists(host, '/root/.bash_history')
    """
    file = host.file(path)
    error_msg = message or f"File {path} should not exist"
    assert not file.exists, error_msg


def assert_file_empty(host, path, message=None):
    """
    Assert that a file is empty or does not exist.

    Args:
        host: testinfra host fixture
        path: File path to check
        message: Optional custom error message

    Example:
        assert_file_empty(host, '/root/.bash_history')
    """
    file = host.file(path)
    if file.exists:
        content_length = len(file.content_string)
        error_msg = message or f"File {path} must be empty (has {content_length} bytes)"
        assert content_length == 0, error_msg


def assert_file_contains(host, path, expected_content, message=None):
    """
    Assert that a file contains the expected content.

    Args:
        host: testinfra host fixture
        path: File path to check
        expected_content: String or pattern to look for
        message: Optional custom error message

    Example:
        assert_file_contains(host, '/etc/cloud/cloud.cfg', 'datasource_list')
    """
    file = host.file(path)
    assert file.exists, f"File {path} does not exist"
    error_msg = message or f"File {path} does not contain '{expected_content}'"
    assert file.contains(expected_content), error_msg


def assert_command_succeeds(host, command, use_sudo=False, message=None):
    """
    Assert that a command executes successfully (exit code 0).

    Args:
        host: testinfra host fixture
        command: Command to execute
        use_sudo: Whether to run with sudo
        message: Optional custom error message

    Returns:
        Command result object (with stdout, stderr, rc)

    Example:
        result = assert_command_succeeds(host, 'systemctl is-active cloud-init')
    """
    if use_sudo:
        with host.sudo():
            result = host.run(command)
    else:
        result = host.run(command)

    error_msg = message or f"Command '{command}' failed with exit code {result.rc}\nStderr: {result.stderr}"
    assert result.succeeded, error_msg
    return result


def assert_command_fails(host, command, use_sudo=False, message=None):
    """
    Assert that a command fails (non-zero exit code).

    Args:
        host: testinfra host fixture
        command: Command to execute
        use_sudo: Whether to run with sudo
        message: Optional custom error message

    Returns:
        Command result object (with stdout, stderr, rc)

    Example:
        assert_command_fails(host, 'systemctl is-active nonexistent.service')
    """
    if use_sudo:
        with host.sudo():
            result = host.run(command)
    else:
        result = host.run(command)

    error_msg = message or f"Command '{command}' should have failed but succeeded"
    assert not result.succeeded, error_msg
    return result


def assert_no_avc_denials(host, message=None):
    """
    Assert that there are no SELinux AVC denials.

    Args:
        host: testinfra host fixture
        message: Optional custom error message

    Example:
        assert_no_avc_denials(host)
    """
    with host.sudo():
        result = host.run('grep -i "avc.*denied" /var/log/audit/audit.log')

    error_msg = message or f"Found AVC denials:\n{result.stdout}"
    assert result.rc != 0, error_msg


def assert_package_installed(host, package_name, message=None):
    """
    Assert that a package is installed.

    Args:
        host: testinfra host fixture
        package_name: Name of package to check
        message: Optional custom error message

    Example:
        assert_package_installed(host, 'cloud-init')
    """
    package = host.package(package_name)
    error_msg = message or f"Package {package_name} is not installed"
    assert package.is_installed, error_msg


def assert_package_not_installed(host, package_name, message=None):
    """
    Assert that a package is not installed.

    Args:
        host: testinfra host fixture
        package_name: Name of package to check
        message: Optional custom error message

    Example:
        assert_package_not_installed(host, 'telnet-server')
    """
    package = host.package(package_name)
    error_msg = message or f"Package {package_name} should not be installed"
    assert not package.is_installed, error_msg


def assert_service_running(host, service_name, message=None):
    """
    Assert that a service is running.

    Args:
        host: testinfra host fixture
        service_name: Name of service to check
        message: Optional custom error message

    Example:
        assert_service_running(host, 'sshd')
    """
    service = host.service(service_name)
    error_msg = message or f"Service {service_name} is not running"
    assert service.is_running, error_msg


def assert_service_enabled(host, service_name, message=None):
    """
    Assert that a service is enabled (starts at boot).

    Args:
        host: testinfra host fixture
        service_name: Name of service to check
        message: Optional custom error message

    Example:
        assert_service_enabled(host, 'cloud-init')
    """
    service = host.service(service_name)
    error_msg = message or f"Service {service_name} is not enabled"
    assert service.is_enabled, error_msg
