import os
from test_suite.test_discovery import split_by_format


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
                 instances: dict,
                 ssh_config: str,
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
        """
        Run tests, auto-detecting format (pytest or YAML).
        
        Supports:
        - pytest test files (.py)
        - YAML test files (.yaml, .yml)
        - Mixed test suites (both formats)
        """
        if os.path.exists(output_filepath):
            os.remove(output_filepath)

        if not test_suite_paths:
            test_suite_paths = self.get_default_test_suite_paths()

        # Split tests by format
        yaml_tests, pytest_tests = split_by_format(test_suite_paths)

        combined_exit_code = 0

        # Run YAML tests if any
        if yaml_tests:
            print('\n' + '='*70)
            print('Running YAML tests')
            print('='*70 + '\n')
            yaml_exit = self._run_yaml_tests(yaml_tests, output_filepath, test_filter, include_markers)
            combined_exit_code = combined_exit_code or yaml_exit

        # Run pytest tests if any
        if pytest_tests:
            print('\n' + '='*70)
            print('Running pytest tests')
            print('='*70 + '\n')
            pytest_exit = self._run_pytest_tests(pytest_tests, output_filepath, test_filter, include_markers)
            combined_exit_code = combined_exit_code or pytest_exit

        return combined_exit_code

    def _run_yaml_tests(self,
                        yaml_test_paths,
                        output_filepath,
                        test_filter=None,
                        include_markers=None):
        """Execute YAML tests using the spike test executor."""
        try:
            from test_suite.yaml_test_runner import YAMLTestRunner
            
            yaml_runner = YAMLTestRunner(
                cloud_provider=self.cloud_provider,
                instances=self.instances,
                ssh_config=self.ssh_config,
                parallel=self.parallel,
                debug=self.debug
            )
            
            # Convert include_markers to tags for YAML tests
            include_tags = None
            if include_markers:
                # Parse markers like "pub" or "not pub"
                include_tags = [m.strip() for m in include_markers.split() if m.strip() != 'not']
            
            # Run YAML tests (use separate output file for YAML to avoid conflicts)
            yaml_output = output_filepath.replace('.xml', '_yaml.xml')
            exit_code = yaml_runner.run_tests(
                yaml_test_paths=yaml_test_paths,
                output_filepath=yaml_output,
                test_filter=test_filter,
                include_tags=include_tags
            )
            
            return exit_code
        
        except ImportError as e:
            print(f"ERROR: Could not import YAML test runner: {e}")
            print("Make sure spike test executor is available in the path")
            return 1
        except Exception as e:
            print(f"ERROR: Failed to run YAML tests: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return 1

    def _run_pytest_tests(self,
                          pytest_test_paths,
                          output_filepath,
                          test_filter=None,
                          include_markers=None):
        """Execute pytest tests using the original pytest runner."""
        pytest_composed_command = self.compose_pytest_command(
            pytest_test_paths,
            output_filepath,
            test_filter,
            include_markers
        )

        if self.debug:
            print('Composed pytest command:')
            print(pytest_composed_command)

        return os.system(pytest_composed_command)


    def compose_pytest_command(self,
                               test_suite_paths,
                               output_filepath,
                               test_filter=None,
                               include_markers=None):
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
