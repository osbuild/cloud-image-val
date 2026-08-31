import os
import subprocess
from unittest.mock import patch

import pytest

from ssh.client import (
    generate_ssh_key_pair,
    wait_for_host_ssh_up,
    add_ssh_keys_to_instances,
    _copy_team_ssh_keys_to_instance,
)


class TestGenerateSSHKeyPair:
    def test_creates_key_files_with_correct_format(self, tmp_path):
        identity_file = str(tmp_path / "test_key")

        priv, pub = generate_ssh_key_pair(identity_file)

        assert os.path.isfile(priv)
        assert os.path.isfile(pub)
        assert oct(os.stat(priv).st_mode & 0o777) == "0o600"

        with open(priv) as f:
            assert f.read().startswith("-----BEGIN RSA PRIVATE KEY-----")
        with open(pub) as f:
            assert f.read().startswith("ssh-rsa ")


class TestWaitForHostSSHUp:
    @patch("ssh.client.subprocess.run")
    def test_returns_when_ssh_is_available(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        wait_for_host_ssh_up("1.2.3.4", timeout_seconds=5)

        mock_run.assert_called_once_with(
            ["ssh-keyscan", "1.2.3.4"], capture_output=True, timeout=10,
        )

    @patch("ssh.client.time.sleep")
    @patch("ssh.client.subprocess.run")
    def test_retries_until_success(self, mock_run, _mock_sleep):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=1),
            subprocess.CompletedProcess(args=[], returncode=0),
        ]

        wait_for_host_ssh_up("1.2.3.4", timeout_seconds=30)

        assert mock_run.call_count == 2

    def test_exits_on_timeout(self):
        with pytest.raises(SystemExit):
            wait_for_host_ssh_up("1.2.3.4", timeout_seconds=0)


class TestCopyTeamSSHKeysToInstance:
    @patch("ssh.client.subprocess.run")
    def test_calls_ssh_with_subprocess_run(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        _copy_team_ssh_keys_to_instance(
            {"address": "10.0.0.1", "username": "ec2-user"},
            "/tmp/ssh_config",
            {"key.pub": "ssh-rsa AAAA"},
        )

        args = mock_run.call_args[0][0]
        assert args[:4] == ["ssh", "-F", "/tmp/ssh_config", "ec2-user@10.0.0.1"]

    @patch("ssh.client.subprocess.run")
    def test_raises_on_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)

        with pytest.raises(AssertionError, match="Could not copy public SSH key"):
            _copy_team_ssh_keys_to_instance(
                {"address": "10.0.0.1", "username": "ec2-user"},
                "/tmp/ssh_config",
                {"key.pub": "ssh-rsa AAAA"},
            )


class TestAddSSHKeysToInstances:
    @patch("ssh.client.subprocess.run")
    @patch("ssh.client._get_team_ssh_keys_by_path", return_value={"key.pub": "ssh-rsa AAAA"})
    def test_copies_keys_to_all_instances(self, _mock_keys, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        instances = {
            "inst1": {"address": "10.0.0.1", "username": "ec2-user"},
            "inst2": {"address": "10.0.0.2", "username": "ec2-user"},
        }

        add_ssh_keys_to_instances(instances, "/tmp/ssh_config")

        assert mock_run.call_count == 2
