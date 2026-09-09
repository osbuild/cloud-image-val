import subprocess
from unittest.mock import patch

from core.executor import execute, _run_on_instance, ExecutionResult, InstanceResult
from core.metadata import InstanceMetadata


def _make_instance(name="test-inst", address="1.2.3.4", username="ec2-user"):
    return InstanceMetadata(
        name=name, address=address, username=username,
        cloud="aws", image="ami-123",
    )


INSTANCES = {"inst1": _make_instance()}


class TestRunOnInstance:
    @patch("core.executor.subprocess.run")
    def test_successful_execution_and_collection(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0),
        ]

        result = _run_on_instance(
            _make_instance(), "echo hello", "/tmp/ssh_config",
            "/tmp/results", "/tmp/results.xml", 3600,
        )

        assert result.exit_code == 0
        assert result.stdout == "ok"
        assert result.result_file is not None

    @patch("core.executor.subprocess.run")
    def test_ssh_uses_list_args(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0),
        ]

        _run_on_instance(
            _make_instance(), "echo hello", "/tmp/ssh_config",
            "/tmp/results", "/tmp/results.xml", 3600,
        )

        ssh_call = mock_run.call_args_list[0]
        assert ssh_call[0][0] == ["ssh", "-F", "/tmp/ssh_config", "ec2-user@1.2.3.4", "echo hello"]

    @patch("core.executor.subprocess.run")
    def test_command_failure(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error"),
            subprocess.CompletedProcess(args=[], returncode=0),
        ]

        result = _run_on_instance(
            _make_instance(), "bad-cmd", "/tmp/ssh_config",
            "/tmp/results", "/tmp/results.xml", 3600,
        )

        assert result.exit_code == 1
        assert result.stderr == "error"

    @patch("core.executor.subprocess.run")
    def test_timeout_skips_scp(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ssh", timeout=10)

        result = _run_on_instance(
            _make_instance(), "slow-cmd", "/tmp/ssh_config",
            "/tmp/results", "/tmp/results.xml", 10,
        )

        assert result.exit_code == 124
        assert "timed out" in result.stderr
        assert result.result_file is None
        assert mock_run.call_count == 1

    @patch("core.executor.subprocess.run")
    def test_ssh_connection_error_skips_scp(self, mock_run):
        mock_run.side_effect = Exception("Connection refused")

        result = _run_on_instance(
            _make_instance(), "cmd", "/tmp/ssh_config",
            "/tmp/results", "/tmp/results.xml", 3600,
        )

        assert result.exit_code == 1
        assert "Connection refused" in result.stderr
        assert result.result_file is None
        assert mock_run.call_count == 1

    @patch("core.executor.subprocess.run")
    def test_scp_failure_sets_result_file_none(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=1),
        ]

        result = _run_on_instance(
            _make_instance(), "cmd", "/tmp/ssh_config",
            "/tmp/results", "/tmp/results.xml", 3600,
        )

        assert result.exit_code == 0
        assert result.result_file is None

    @patch("core.executor.subprocess.run")
    def test_scp_exception_sets_result_file_none(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            Exception("scp failed"),
        ]

        result = _run_on_instance(
            _make_instance(), "cmd", "/tmp/ssh_config",
            "/tmp/results", "/tmp/results.xml", 3600,
        )

        assert result.result_file is None


class TestExecute:
    @patch("core.executor._run_on_instance")
    @patch("core.executor.os.makedirs")
    def test_returns_execution_result(self, mock_makedirs, mock_run):
        mock_run.return_value = InstanceResult(
            instance_name="test-inst", exit_code=0,
            result_file="/tmp/results/instance-test-inst.xml",
            stdout="ok", stderr="",
        )

        result = execute(INSTANCES, "echo hello", "/tmp/ssh_config", "/tmp/results")

        assert isinstance(result, ExecutionResult)
        assert len(result.instance_results) == 1
        assert result.all_passed is True

    @patch("core.executor._run_on_instance")
    @patch("core.executor.os.makedirs")
    def test_all_passed_false_on_failure(self, mock_makedirs, mock_run):
        mock_run.return_value = InstanceResult(
            instance_name="test-inst", exit_code=1,
            result_file=None, stdout="", stderr="fail",
        )

        result = execute(INSTANCES, "bad-cmd", "/tmp/ssh_config", "/tmp/results")

        assert result.all_passed is False

    @patch("core.executor._run_on_instance")
    @patch("core.executor.os.makedirs")
    def test_multiple_instances(self, mock_makedirs, mock_run):
        mock_run.side_effect = [
            InstanceResult("inst-a", 0, "/tmp/r/a.xml", "ok", ""),
            InstanceResult("inst-b", 1, None, "", "fail"),
        ]

        instances = {
            "a": _make_instance(name="inst-a", address="1.1.1.1"),
            "b": _make_instance(name="inst-b", address="2.2.2.2"),
        }

        result = execute(instances, "cmd", "/tmp/ssh_config", "/tmp/r")

        assert len(result.instance_results) == 2
        assert result.all_passed is False

    @patch("core.executor._run_on_instance")
    @patch("core.executor.os.makedirs")
    def test_creates_results_dir(self, mock_makedirs, mock_run):
        mock_run.return_value = InstanceResult(
            instance_name="test-inst", exit_code=0,
            result_file=None, stdout="", stderr="",
        )

        execute(INSTANCES, "cmd", "/tmp/ssh_config", "/tmp/results")

        mock_makedirs.assert_called_once_with("/tmp/results", exist_ok=True)


class TestExecutionResult:
    def test_all_passed_true(self):
        result = ExecutionResult(instance_results=[
            InstanceResult("a", 0, None, "", ""),
            InstanceResult("b", 0, None, "", ""),
        ])
        assert result.all_passed is True

    def test_all_passed_false(self):
        result = ExecutionResult(instance_results=[
            InstanceResult("a", 0, None, "", ""),
            InstanceResult("b", 1, None, "", ""),
        ])
        assert result.all_passed is False

    def test_empty_results(self):
        result = ExecutionResult(instance_results=[])
        assert result.all_passed is True
