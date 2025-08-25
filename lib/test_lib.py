from os import path
import re
import time

from lib import ssh_lib, console_lib


def is_rhel_sap(host):
    return __test_keyword_in_repositories(host, 'sap-')


def is_rhel_high_availability(host):
    rhui_pkg = str(host.run('rpm -qa | grep rhui').stdout)
    return re.search('rhui-(?!sap).*ha', rhui_pkg)


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
    :return: testinfra.backend.base.CommandResult containing: command, rc, stdout, stderr
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

    time.sleep(10)

    ssh_lib.wait_for_host_ssh_up(hostname, max_timeout)

    new_host = host.get_host(f'paramiko://{username}@{hostname}',
                             ssh_config=host.backend.ssh_config)

    # If reboot_count is the same after reboot attempt, the system did not reboot
    if int(new_host.check_output(last_boot_count_cmd)) == reboot_count:
        raise Exception(f'Failed to reboot instance.\n'
                        f'\tstatus:\t{result.rc}\n'
                        f'\tstdout:\t{result.stdout}\n'
                        f'\tstderr:\t{result.stderr}')

    return new_host


def get_host_last_boot_time(host):
    """
    Get system boot time via "systemd-analyze"
    :param host: The testinfra host object, from pytest test case
    :return: (float) Boot time, in seconds
    """
    timeout_seconds = 60

    with host.sudo():
        start_time = time.time()
        while time.time() < start_time + timeout_seconds:
            systemd_analyze_result = host.run('systemd-analyze')
            if systemd_analyze_result.exit_status == 0 and \
                    'Startup finished' in systemd_analyze_result.stdout:
                break
            time.sleep(5)

        print(host.run('systemd-analyze blame').stdout, end='\n-------\n')
        print(host.run('systemd-analyze').stdout)

    boot_time_string = re.findall('Startup finished .* = (.*)s',
                                  systemd_analyze_result.stdout)[0]

    if 'min' in boot_time_string:
        boot_time_data = re.match(r'(\d+)min (\d+.\d+)', boot_time_string)

        if boot_time_data:
            boot_time_data = boot_time_data.groups()
            minutes = float(boot_time_data[0])
            seconds = float(boot_time_data[1])

            if seconds > 60:
                # This means it's miliseconds, not seconds
                seconds /= 1000

            boot_time = (minutes * 60) + seconds
        else:
            raise Exception(f'Could not obtain boot time from systemd-analyze output: {boot_time_string}')
    else:
        boot_time = float(boot_time_string)

    return float(boot_time)


def compare_local_and_remote_file(host,
                                  local_file_path,
                                  remote_file_path,
                                  ignore_commented_lines=True,
                                  ignore_space_and_blank=True):
    tmp_path = f'/tmp/test_file_{time.time()}'

    diff_command = ['diff']

    if ignore_space_and_blank:
        diff_command.append('-wB')

    if ignore_commented_lines:
        diff_command.append('-I "^#" -I "^ #"')

    diff_command.extend([remote_file_path, tmp_path])

    ssh_lib.copy_file_to_host(host, local_file_path, tmp_path)

    with host.sudo():
        if not host.file(remote_file_path).exists:
            raise FileNotFoundError(f'The remote file {remote_file_path} was not found')

        result = host.run(' '.join(diff_command))
        print(result.stdout)

        host.run(f'rm -rf {tmp_path}')

        return result.exit_status == 0


def filter_host_log_file_by_keywords(host,
                                     log_file,
                                     log_levels,
                                     keywords=None,
                                     exclude_mode=False):
    """
    Filters a log file by log levels, and then by a list of keywords.
    If exclude_mode is set to True, the keywords will be used for inverted match.
    :param host: The host to connect to, from testinfra's module
    :param log_file: Path to the file that needs to be filtered
    :param log_levels: The log levels that need to be taken into account for filtering
    :param keywords: List of keywords to use as secondary filter, after filtering by log level
    :param exclude_mode: Whether to use inverted match with the keywords or not
    :return: String with all the log lines found, matching the criteria
    """
    log_levels_regex = '|'.join(log_levels)

    if keywords is not None:
        keywords_regex = '|'.join(keywords)
        if exclude_mode:
            search_opt = '-vE'
            print('exclude_mode set to True. Keywords will be used for inverted match')
        else:
            search_opt = '-E'
        grep_filter_by_keyword = ' | grep {} "{}"'.format(search_opt, keywords_regex)
    else:
        grep_filter_by_keyword = ''

    print(f'Filtering {log_file} log file...')

    with host.sudo():
        result = host.run('grep -iE "{}" "{}"{}'.format(log_levels_regex,
                                                        log_file,
                                                        grep_filter_by_keyword))
        if result.rc == 0:
            print(f'Logs found:\n{result.stdout}')
            return result.stdout
        else:
            print('No logs found.')
            print(result.stderr)

        return None


def print_host_command_output(host, command, capture_result=False, use_sudo=True):
    console_lib.print_divider(command)

    if use_sudo:
        with host.sudo():
            result = host.run(command)
    else:
        result = host.run(command)

    if result.failed:
        print(f'Exit code: {result.exit_status}\n')
        print(f'Stdout:\n{result.stdout}\n')
        print(f'Stderr:\n{result.stderr}\n')
    else:
        print(result.stdout)

    if capture_result:
        return result
