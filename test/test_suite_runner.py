import pytest

from test_suite.suite_runner import SuiteRunner


class TestSuiteRunner:
    test_cloud_provider = 'aws'
    test_instances = ['test instance 1', 'test instance 2']
    test_ssh_config = '/path/to/ssh_config'
    test_output_filepath = 'test/output/filepath.xml'
    test_filter = 'test_test_name'
    test_marker = 'pub'
    test_connection = 'paramiko'

    @pytest.fixture
    def suite_runner(self):
        return SuiteRunner(self.test_cloud_provider,
                           self.test_instances,
                           self.test_ssh_config)

    def test_run_tests(self, mocker, suite_runner):
        # Arrange
        test_output_filepath = '/test/output/filepath'
        test_composed_command = 'test composed command'

        mock_compose_testinfra_command = mocker.MagicMock(return_value=test_composed_command)
        suite_runner.compose_testinfra_command = mock_compose_testinfra_command

        mock_os_path_exists = mocker.patch('os.path.exists', return_value=True)
        mock_os_remove = mocker.patch('os.remove')
        mock_os_system = mocker.patch('os.system')

        # Act
        suite_runner.run_tests(test_output_filepath, self.test_filter, self.test_marker)

        # Assert
        mock_os_path_exists.assert_called_once_with(test_output_filepath)
        mock_os_remove.assert_called_once_with(test_output_filepath)

        mock_os_system.assert_called_once_with(test_composed_command)
        mock_compose_testinfra_command.assert_called_once_with(test_output_filepath,
                                                               self.test_filter,
                                                               self.test_marker)

    @pytest.mark.parametrize(
        'test_filter, test_marker, test_debug, test_parallel, expected_command_string',
        [(None, None, False, False,
          'py.test path1 path2 --hosts=user1@host1,user2@host2 '
          f'--connection={test_connection} '
          f'--ssh-config {test_ssh_config} --junit-xml {test_output_filepath} '
          f'--html {test_output_filepath.replace("xml", "html")} '
          f'--self-contained-html'),
         (test_filter, test_marker, False, False,
          'py.test path1 path2 --hosts=user1@host1,user2@host2 '
          f'--connection={test_connection} '
          f'--ssh-config {test_ssh_config} --junit-xml {test_output_filepath} '
          f'--html {test_output_filepath.replace("xml", "html")} '
          f'--self-contained-html '
          f'-k "{test_filter}" '
          f'-m "{test_marker}"'),
         (None, None, False, True,
          'py.test path1 path2 --hosts=user1@host1,user2@host2 '
          f'--connection={test_connection} '
          f'--ssh-config {test_ssh_config} --junit-xml {test_output_filepath} '
          f'--html {test_output_filepath.replace("xml", "html")} '
          f'--self-contained-html '
          f'--numprocesses={len(test_instances)} --maxprocesses=40 '
          '--only-rerun="socket.timeout|refused|ConnectionResetError|TimeoutError|SSHException|NoValidConnectionsError" '
          '--reruns 3 --reruns-delay 5'),
         (None, None, True, True,
          'py.test path1 path2 --hosts=user1@host1,user2@host2 '
          f'--connection={test_connection} '
          f'--ssh-config {test_ssh_config} --junit-xml {test_output_filepath} '
          f'--html {test_output_filepath.replace("xml", "html")} '
          f'--self-contained-html '
          f'--numprocesses={len(test_instances)} --maxprocesses=40 '
          '--only-rerun="socket.timeout|refused|ConnectionResetError|TimeoutError|SSHException|NoValidConnectionsError" '
          '--reruns 3 --reruns-delay 5 '
          '-v')]
    )
    def test_compose_testinfra_command(self,
                                       mocker,
                                       suite_runner,
                                       test_filter,
                                       test_marker,
                                       test_debug,
                                       test_parallel,
                                       expected_command_string):
        # Arrange
        test_hosts = 'user1@host1,user2@host2'
        test_suite_paths = ['path1', 'path2']

        suite_runner.debug = test_debug
        suite_runner.parallel = test_parallel

        mock_get_all_instances_hosts_with_users = mocker.MagicMock(return_value=test_hosts)
        suite_runner.get_all_instances_hosts_with_users = mock_get_all_instances_hosts_with_users

        mock_get_test_suite_paths = mocker.MagicMock(return_value=test_suite_paths)
        suite_runner.get_test_suite_paths = mock_get_test_suite_paths

        # Act, Assert
        assert suite_runner.compose_testinfra_command(self.test_output_filepath,
                                                      test_filter,
                                                      test_marker) == expected_command_string

        mock_get_all_instances_hosts_with_users.assert_called_once()

    @pytest.mark.parametrize(
        'test_instances, expected_hosts',
        [(dict(instance_1={'username': 'user1', 'public_dns': 'host1'}), 'user1@host1'),
         (dict(instance_1={'username': 'user1', 'public_dns': 'host1'},
               instance_2={'username': 'user2', 'public_dns': 'host2'},
               instance_3={'username': 'user3', 'public_dns': 'host3'}), 'user1@host1,user2@host2,user3@host3')]
    )
    def test_get_all_instances_hosts_with_users(self, suite_runner, test_instances, expected_hosts):
        suite_runner.instances = test_instances

        assert suite_runner.get_all_instances_hosts_with_users() == expected_hosts

    @pytest.mark.parametrize(
        'test_instances, exception',
        [(dict(instance_1={'wrong_key_for_username': 'user1', 'public_dns': 'host1'}),
          pytest.raises(KeyError))]
    )
    def test_get_all_instances_hosts_with_users_exception(self, suite_runner, test_instances, exception):
        suite_runner.instances = test_instances

        with exception:
            suite_runner.get_all_instances_hosts_with_users()

    @pytest.mark.parametrize(
        'test_cloud_provider, expected_suite_paths',
        [('other', ['generic/test_generic.py']),
         ('aws', ['generic/test_generic.py', 'cloud/test_aws.py'])],
    )
    def test_get_test_suite_paths(self,
                                  mocker,
                                  suite_runner,
                                  test_cloud_provider,
                                  expected_suite_paths):
        suite_runner.cloud_provider = test_cloud_provider

        mocker.patch('os.path.dirname', return_value='')

        assert suite_runner.get_test_suite_paths() == expected_suite_paths
