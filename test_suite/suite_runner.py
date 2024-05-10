import os


class SuiteRunner:
    max_processes = 162  # This is the maximum amount of images we have successfully tested in parallel (AWS)

    # Rerun failed tests in case ssh times out or connection is refused by host
    rerun_failing_tests_regex = '|'.join([
        'socket.timeout',
        'refused',
        'ConnectionResetError',
        'TimeoutError',
        'SSHException',
        'NoValidConnectionsError',
        'Error while installing Development tools group'
    ])

    connection_backend = 'paramiko'
    max_reruns = 3
    rerun_delay_sec = 5

    def __init__(self,
                 cloud_provider,
                 instances,
                 ssh_config,
                 parallel=True,
                 debug=False):
        self.cloud_provider = cloud_provider
        self.instances = instances
        self.ssh_config = ssh_config
        self.parallel = parallel
        self.debug = debug

    def run_tests(self,
                  test_suite_paths,
                  output_filepath,
                  test_filter=None,
                  include_markers=None):
        if os.path.exists(output_filepath):
            os.remove(output_filepath)

        pytest_composed_command = self.compose_pytest_command(test_suite_paths,
                                                              output_filepath,
                                                              test_filter,
                                                              include_markers)

        if self.debug:
            print('Composed pytest command:')
            print(pytest_composed_command)

        return os.system(pytest_composed_command)

    def compose_pytest_command(self,
                               test_suite_paths,
                               output_filepath,
                               test_filter,
                               include_markers):
        all_hosts = self.get_all_instances_hosts_with_users()

        if not test_suite_paths:
            test_suite_paths = self.get_default_test_suite_paths()

        command_with_args = [
            'pytest',
            ' '.join(test_suite_paths),
            f'--hosts={all_hosts}',
            f'--connection={self.connection_backend}',
            f'--ssh-config {self.ssh_config}',
            f'--junit-xml {output_filepath}',
            f'--html {output_filepath.replace("xml", "html")}',
            '--self-contained-html',
            f'--json-report --json-report-file={output_filepath.replace("xml", "json")}'
        ]

        if test_filter:
            command_with_args.append(f'-k "{test_filter}"')

        if include_markers:
            command_with_args.append(f'-m "{include_markers}"')

        if self.parallel:
            command_with_args.append(f'--numprocesses={len(self.instances)}')
            command_with_args.append(f'--maxprocesses={self.max_processes}')

            command_with_args.append(f'--only-rerun="{self.rerun_failing_tests_regex}"')
            command_with_args.append(f'--reruns {self.max_reruns}')
            command_with_args.append(f'--reruns-delay {self.rerun_delay_sec}')

        if self.debug:
            command_with_args.append('-v')

        return ' '.join(command_with_args)

    def get_default_test_suite_paths(self):
        """
        :return: A list of test suite file paths that will be used in case there are no test suites passed as argument
        """
        test_suites_to_run = ['generic/test_generic.py']

        if self.cloud_provider == 'aws':
            test_suites_to_run.append('cloud/test_aws.py')
        elif self.cloud_provider == 'azure':
            test_suites_to_run.append('cloud/test_azure.py')

        return [os.path.join(os.path.dirname(__file__), p) for p in test_suites_to_run]

    def get_all_instances_hosts_with_users(self):
        """
        :return: A string with comma-separated items in the form of '<user1>@<host1>,<user2>@<host2>'
        """
        return ','.join(['{0}@{1}'.format(inst['username'], inst['address']) for inst in self.instances.values()])
