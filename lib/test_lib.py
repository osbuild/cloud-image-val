from os import path
from lib import ssh_lib


def is_rhel_atomic_host(host):
    with host.sudo():
        return host.file('/etc/redhat-release').contains('Atomic')


def is_rhel_sap(host):
    return __test_keyword_in_repositories(host, 'sap-bundle')


def is_rhel_high_availability(host):
    return __test_keyword_in_repositories(host, 'highavailability')


def __test_keyword_in_repositories(host, keyword):
    with host.sudo():
        if host.exists('yum'):
            return keyword in host.run('yum repolist 2>&1').stdout


def run_local_script_in_host(host, script_relative_path):
    """
    Runs a local script in the given remote host.
    To achieve this, the script is first copied to the remote host.
    :param host: The host object from the pytest test case.
    :param script_relative_path: Relative file path of the script to run (from project's root dir)
    :return: testinfra.backend.base.CommandResult containing: command, exit_status, stdout, stderr
    """
    script_remote_path = f'/tmp/{path.basename(script_relative_path)}'

    ssh_lib.copy_file_to_host(host, script_relative_path, script_remote_path)

    with host.sudo():
        host.run_test(f'chmod +x "{script_remote_path}"')
        return host.run(script_remote_path)
