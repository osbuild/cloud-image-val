import pytest
import os

from cloud.terraform.terraform_controller import TerraformController


class TestTerraformController:
    test_ssh_key = '/fake/ssh/dir'
    test_resources_path = '/fake/resources/path'

    def tf_configurator(self, mocker):
        tf_configurator = mocker.MagicMock()
        return tf_configurator

    @pytest.fixture
    def tf_controller(self, mocker):
        self.tf_configurator = self.tf_configurator(mocker)
        return TerraformController(self.tf_configurator)

    def test_create_infra(self, mocker, tf_controller):
        # Arrange
        mock_os_system = mocker.patch('os.system', return_value='')
        tf_init = 'terraform init'
        tf_apply = 'terraform apply -auto-approve'

        # Acts
        result = tf_controller.create_infra()

        # Assert
        assert result is None
        mock_os_system.assert_has_calls([mocker.call(tf_init), mocker.call(tf_apply)])

    @pytest.mark.parametrize('cloud', ['aws'])
    def test_get_instances(self, mocker, tf_controller, cloud):
        # Arrange
        tf_controller.cloud = cloud

        mock_popen = mocker.patch('os.popen', return_value=os._wrap_close)

        mock_read = mocker.MagicMock(return_value='test_json')
        os._wrap_close.read = mock_read

        mock_loads = mocker.patch('json.loads',
                                  return_value={'values': {'root_module': {'resources': 'test'}}})

        test_dict = {'test_dict': 42}
        mock_get_instances_cloud = mocker.MagicMock(return_value=test_dict)
        if cloud == 'aws':
            tf_controller.get_instances_aws = mock_get_instances_cloud

        # Act
        result = tf_controller.get_instances()

        # Assert
        mock_popen.assert_called_once_with('terraform show --json')
        mock_read.assert_called_once()
        mock_loads.called_once_with('test_json')
        mock_get_instances_cloud.assert_called_once_with('test')
        assert result == test_dict

    def test_get_instances_aws(self, mocker, tf_controller):
        # Arrange
        resources = [
            {
                'address': 'a.aws_instance_test',
                'values': {
                    'id': 'test_id',
                    'public_ip': 'test_ip',
                    'public_dns': 'test_dns',
                    'availability_zone': 'test_zone',
                    'ami': 'test_ami',
                },
            },
            {'address': 'a.not_an_instance'},
        ]

        instances_info_expected = {
            'a.aws_instance_test': {
                'instance_id': 'test_id',
                'public_ip': 'test_ip',
                'public_dns': 'test_dns',
                'availability_zone': 'test_zone',
                'ami': 'test_ami',
                'username': 'test_user',
            }
        }

        mock_get_username_by_instance_name = mocker.MagicMock(return_value='test_user')
        self.tf_configurator.get_username_by_instance_name = (mock_get_username_by_instance_name)

        # Act
        result = tf_controller.get_instances_aws(resources)

        # Assert
        mock_get_username_by_instance_name.assert_called_once_with('aws_instance_test')
        assert result == instances_info_expected

    def test_destroy_resource(self, mocker, tf_controller):
        # Arrange
        mock_os_system = mocker.patch('os.system', return_value='')
        test_resource_id = 'test_resource'
        tf_destroy_resource = f'terraform destroy -target={test_resource_id}'

        # Act
        result = tf_controller.destroy_resource(test_resource_id)

        # Assert
        assert result is None
        mock_os_system.assert_called_once_with(tf_destroy_resource)

    def test_destroy_infra(self, mocker, tf_controller):
        # Arrange
        mock_os_system = mocker.patch('os.system', return_value='')
        tf_destroy_infra = 'terraform destroy -auto-approve'

        # Act
        result = tf_controller.destroy_infra()

        # Assert
        assert result is None
        mock_os_system.assert_called_once_with(tf_destroy_infra)
