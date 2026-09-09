from unittest.mock import patch

import pytest

from core.config import CoreConfig
from core.metadata import InstanceMetadata
from core.provisioner import Provisioner


def _make_config(**overrides):
    defaults = {
        "resources_file": "resources.json",
        "output_file": "output.xml",
    }
    defaults.update(overrides)
    return CoreConfig(**defaults)


RAW_INSTANCE = {
    "aws_instance.test": {
        "name": "test-instance",
        "address": "1.2.3.4",
        "username": "ec2-user",
        "cloud": "aws",
        "image": "ami-123",
    }
}


class TestProvision:
    @patch("core.provisioner.write_ssh_config")
    @patch("core.provisioner.write_instances_json")
    @patch("core.provisioner.generate_ssh_key_pair")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_returns_typed_instances(
        self, MockConfigurator, MockController, mock_keygen, mock_write_json, mock_write_ssh,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config()
        provisioner = Provisioner(config)
        instances = provisioner.provision()

        assert "aws_instance.test" in instances
        assert isinstance(instances["aws_instance.test"], InstanceMetadata)
        assert instances["aws_instance.test"].address == "1.2.3.4"

    @patch("core.provisioner.write_ssh_config")
    @patch("core.provisioner.write_instances_json")
    @patch("core.provisioner.generate_ssh_key_pair")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_generates_ssh_keys(
        self, MockConfigurator, MockController, mock_keygen, mock_write_json, mock_write_ssh,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config(ssh_identity_file="/tmp/test-key")
        provisioner = Provisioner(config)
        provisioner.provision()

        mock_keygen.assert_called_once_with("/tmp/test-key")

    @patch("core.provisioner.write_ssh_config")
    @patch("core.provisioner.write_instances_json")
    @patch("core.provisioner.generate_ssh_key_pair")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_writes_metadata_files(
        self, MockConfigurator, MockController, mock_keygen, mock_write_json, mock_write_ssh,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config()
        provisioner = Provisioner(config)
        provisioner.provision()

        mock_write_json.assert_called_once()
        mock_write_ssh.assert_called_once()

    @patch("core.provisioner.write_ssh_config")
    @patch("core.provisioner.write_instances_json")
    @patch("core.provisioner.generate_ssh_key_pair")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_creates_infra(
        self, MockConfigurator, MockController, mock_keygen, mock_write_json, mock_write_ssh,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config()
        provisioner = Provisioner(config)
        provisioner.provision()

        mock_controller.create_infra.assert_called_once()

    @patch("core.provisioner.write_ssh_config")
    @patch("core.provisioner.write_instances_json")
    @patch("core.provisioner.generate_ssh_key_pair")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_configures_opentofu(
        self, MockConfigurator, MockController, mock_keygen, mock_write_json, mock_write_ssh,
    ):
        mock_configurator = MockConfigurator.return_value
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config()
        provisioner = Provisioner(config)
        provisioner.provision()

        mock_configurator.configure_from_resources_json.assert_called_once()


class TestGetInstances:
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_returns_typed_instances(self, MockConfigurator, MockController):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config()
        provisioner = Provisioner(config)
        instances = provisioner.get_instances()

        assert "aws_instance.test" in instances
        assert isinstance(instances["aws_instance.test"], InstanceMetadata)


class TestCleanup:
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_destroys_infra(self, MockConfigurator, MockController):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config()
        provisioner = Provisioner(config)
        provisioner.get_instances()
        provisioner.cleanup()

        mock_controller.destroy_infra.assert_called_once()

    def test_cleanup_without_controller(self):
        config = _make_config()
        provisioner = Provisioner(config)
        provisioner.cleanup()

    @patch("core.provisioner.os.remove")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_removes_temp_files_when_not_debug(
        self, MockConfigurator, MockController, mock_remove,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config(debug=False)
        provisioner = Provisioner(config)
        provisioner.get_instances()
        provisioner.cleanup()

        assert mock_remove.call_count == 4

    @patch("core.provisioner.os.remove")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_skips_file_removal_in_debug(
        self, MockConfigurator, MockController, mock_remove,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config(debug=True)
        provisioner = Provisioner(config)
        provisioner.get_instances()
        provisioner.cleanup()

        mock_remove.assert_not_called()

    @patch("core.provisioner.os.remove", side_effect=FileNotFoundError)
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_handles_missing_temp_files(
        self, MockConfigurator, MockController, mock_remove,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE

        config = _make_config(debug=False)
        provisioner = Provisioner(config)
        provisioner.get_instances()
        provisioner.cleanup()

    @patch("core.provisioner.os.remove")
    @patch("core.provisioner.OpenTofuController")
    @patch("core.provisioner.OpenTofuConfigurator")
    def test_removes_files_when_destroy_infra_fails(
        self, MockConfigurator, MockController, mock_remove,
    ):
        mock_controller = MockController.return_value
        mock_controller.get_instances.return_value = RAW_INSTANCE
        mock_controller.destroy_infra.side_effect = Exception("tofu destroy failed")

        config = _make_config(debug=False)
        provisioner = Provisioner(config)
        provisioner.get_instances()

        with pytest.raises(Exception, match="tofu destroy failed"):
            provisioner.cleanup()

        assert mock_remove.call_count == 4


class TestPrepareEnvironment:
    @patch("core.provisioner.add_ssh_keys_to_instances")
    def test_copies_ssh_keys(self, mock_add_keys):
        config = _make_config()
        provisioner = Provisioner(config)

        instances = {
            "inst1": InstanceMetadata(
                name="test", address="1.2.3.4", username="ec2-user",
                cloud="aws", image="ami-123",
            ),
        }
        provisioner.prepare_environment(instances)

        mock_add_keys.assert_called_once()
