from os import path
import re
import time

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


def reboot_host(host, max_timeout=120):
    """
    Reboots the given testinfra's host and uses a timeout to check when the host shh is up again.
    :param host: The testinfra host object, from pytest test case
    :param max_timeout: timeout in seconds, as a limit for the reboot to finish (until the ssh connection is ready)
    :return: A new testinfra host object, which will allow a successful reconnection via ssh
    """
    last_boot_count_cmd = 'last reboot | grep "system boot" | wc -l'
    reboot_count = int(host.check_output(last_boot_count_cmd))

    hostname = host.backend.hostname
    username = host.user().name

    print('Rebooting...')
    with host.sudo():
        result = host.run('shutdown -r now')

    time.sleep(5)

    ssh_lib.wait_for_host_ssh_up(hostname, max_timeout)

    new_host = host.get_host(f'paramiko://{username}@{hostname}', ssh_config=host.backend.ssh_config)

    if int(new_host.check_output(last_boot_count_cmd)) != reboot_count + 1:
        raise Exception(f'Failed to reboot instance.\n'
                        f'\tstatus:\t{result.exit_status}\n'
                        f'\tstdout:\t{result.stdout}\n'
                        f'\tstderr:\t{result.stderr}')

    return new_host


def get_host_last_boot_time(host):
    """
    Get system boot time via "systemd-analyze"
    :param host: The testinfra host object, from pytest test case
    :return: (float) Boot time, in seconds
    """
    with host.sudo():
        systemd_analyze_output = host.check_output('systemd-analyze')

    print(host.run('systemd-analyze blame').stdout)

    return float(re.findall('Startup finished .* = (.*)s', systemd_analyze_output)[0])
