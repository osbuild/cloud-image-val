import os
import subprocess

import pytest

from ssh.client import (
    generate_ssh_key_pair,
    wait_for_host_ssh_up,
    add_ssh_keys_to_instances,
    _copy_team_ssh_keys_to_instance,
    _get_team_ssh_keys_by_path,
)


class TestGenerateSSHKeyPair:
    def test_creates_private_and_public_key_files(self, tmp_path):
        identity_file = str(tmp_path / "test_key")

        priv, pub = generate_ssh_key_pair(identity_file)

        assert priv == identity_file
        assert pub == identity_file + ".pub"
        assert os.path.isfile(identity_file)
        assert os.path.isfile(identity_file + ".pub")

    def test_private_key_has_correct_permissions(self, tmp_path):
        identity_file = str(tmp_path / "test_key")

        generate_ssh_key_pair(identity_file)

        mode = oct(os.stat(identity_file).st_mode & 0o777)
        assert mode == "0o600"

    def test_public_key_is_openssh_format(self, tmp_path):
        identity_file = str(tmp_path / "test_key")

        generate_ssh_key_pair(identity_file)

        with open(identity_file + ".pub", "r") as f:
            content = f.read()
        assert content.startswith("ssh-rsa ")

    def test_private_key_is_pem_format(self, tmp_path):
        identity_file = str(tmp_path / "test_key")

        generate_ssh_key_pair(identity_file)

        with open(identity_file, "r") as f:
            content = f.read()
        assert content.startswith("-----BEGIN RSA PRIVATE KEY-----")


class TestWaitForHostSSHUp:
    def test_returns_when_ssh_is_available(self, mocker):
        mocker.patch(
            "ssh.client.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["ssh-keyscan", "1.2.3.4"],
                returncode=0,
            ),
        )

        wait_for_host_ssh_up("1.2.3.4", timeout_seconds=5)

    def test_retries_until_success(self, mocker):
        mock_run = mocker.patch(
            "ssh.client.subprocess.run",
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=1),
                subprocess.CompletedProcess(args=[], returncode=1),
                subprocess.CompletedProcess(args=[], returncode=0),
            ],
        )
        mocker.patch("ssh.client.time.sleep")

        wait_for_host_ssh_up("1.2.3.4", timeout_seconds=30)

        assert mock_run.call_count == 3

    def test_calls_subprocess_with_list_args(self, mocker):
        mock_run = mocker.patch(
            "ssh.client.subprocess.run",
            return_value=subprocess.CompletedProcess(args=[], returncode=0),
        )

        wait_for_host_ssh_up("10.0.0.1", timeout_seconds=5)

        mock_run.assert_called_once_with(
            ["ssh-keyscan", "10.0.0.1"],
            capture_output=True,
            timeout=10,
        )

    def test_exits_on_timeout(self, mocker):
        mocker.patch(
            "ssh.client.subprocess.run",
            return_value=subprocess.CompletedProcess(args=[], returncode=1),
        )
        mocker.patch("ssh.client.time.sleep")
        mocker.patch(
            "ssh.client.time.time",
            side_effect=[0, 0, 0, 0, 100],
        )

        with pytest.raises(SystemExit):
            wait_for_host_ssh_up("1.2.3.4", timeout_seconds=5)


class TestCopyTeamSSHKeysToInstance:
    def test_calls_ssh_with_correct_args(self, mocker):
        mock_run = mocker.patch(
            "ssh.client.subprocess.run",
            return_value=subprocess.CompletedProcess(args=[], returncode=0),
        )
        instance = {"address": "10.0.0.1", "username": "ec2-user"}
        team_keys = {"key1.pub": "ssh-rsa AAAA"}

        _copy_team_ssh_keys_to_instance(instance, "/tmp/ssh_config", team_keys)

        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "ssh"
        assert call_args[1] == "-F"
        assert call_args[2] == "/tmp/ssh_config"
        assert call_args[3] == "ec2-user@10.0.0.1"

    def test_raises_on_failure(self, mocker):
        mocker.patch(
            "ssh.client.subprocess.run",
            return_value=subprocess.CompletedProcess(args=[], returncode=1),
        )
        instance = {"address": "10.0.0.1", "username": "ec2-user"}

        with pytest.raises(AssertionError, match="Could not copy public SSH key"):
            _copy_team_ssh_keys_to_instance(
                instance, "/tmp/ssh_config", {"k.pub": "ssh-rsa AAAA"}
            )


class TestGetTeamSSHKeysByPath:
    def test_reads_keys_from_directory(self, mocker, tmp_path):
        keys_dir = tmp_path / "team_ssh_keys"
        keys_dir.mkdir()
        (keys_dir / "user1.pub").write_text("ssh-rsa AAAA user1")
        (keys_dir / "user2.pub").write_text("ssh-rsa BBBB user2")

        mocker.patch("ssh.client.os.listdir", return_value=["user1.pub", "user2.pub"])
        mocker.patch("ssh.client.os.path.join", side_effect=[
            str(keys_dir / "user1.pub"),
            str(keys_dir / "user2.pub"),
        ])

        result = _get_team_ssh_keys_by_path()

        assert len(result) == 2
        assert "ssh-rsa AAAA user1" in result.values()
        assert "ssh-rsa BBBB user2" in result.values()


class TestAddSSHKeysToInstances:
    def test_copies_keys_to_all_instances(self, mocker):
        mocker.patch(
            "ssh.client._get_team_ssh_keys_by_path",
            return_value={"key1.pub": "ssh-rsa AAAA"},
        )
        mock_copy = mocker.patch("ssh.client._copy_team_ssh_keys_to_instance")

        instances = {
            "inst1": {"address": "10.0.0.1", "username": "ec2-user"},
            "inst2": {"address": "10.0.0.2", "username": "ec2-user"},
        }

        add_ssh_keys_to_instances(instances, "/tmp/ssh_config")

        assert mock_copy.call_count == 2
