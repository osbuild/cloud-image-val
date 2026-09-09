import sys
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest


mock_provisioner_module = MagicMock()
mock_executor_module = MagicMock()

sys.modules.setdefault("core.provisioner", mock_provisioner_module)
sys.modules.setdefault("core.executor", mock_executor_module)

from cli import (  # noqa: E402
    _build_config,
    _build_test_command,
    _load_instances,
    _parse_tags,
    build_parser,
    cmd_cleanup,
    cmd_collect,
    cmd_execute,
    cmd_provision,
    cmd_run,
    main,
)
from core.config import CoreConfig  # noqa: E402
from core.results import MergeResult  # noqa: E402


def _provision_args(**overrides):
    defaults = {
        "resources_file": "resources.json",
        "config_file": None,
        "debug": False,
        "tags": None,
        "parallel": False,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


def _run_args(**overrides):
    defaults = {
        "resources_file": "resources.json",
        "config_file": None,
        "output_file": "/tmp/out.xml",
        "test_filter": None,
        "test_suites": None,
        "include_markers": None,
        "parallel": False,
        "debug": False,
        "stop_cleanup": False,
        "environment": None,
        "tags": None,
        "command": None,
        "timeout": 3600,
        "attach": False,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


class TestParseTags:
    def test_parses_single_tag(self):
        assert _parse_tags("env:prod") == {"env": "prod"}

    def test_parses_multiple_tags(self):
        result = _parse_tags("env:prod, team:qa")
        assert result == {"env": "prod", "team": "qa"}

    def test_handles_colons_in_value(self):
        result = _parse_tags("url:http://example.com")
        assert result == {"url": "http://example.com"}


class TestBuildConfig:
    def test_builds_from_cli_flags(self):
        args = _provision_args()
        config = _build_config(args)
        assert config.resources_file == "resources.json"
        assert config.debug is False

    def test_builds_with_debug(self):
        args = _provision_args(debug=True)
        config = _build_config(args)
        assert config.debug is True

    def test_builds_with_tags(self):
        args = _provision_args(tags="env:prod")
        config = _build_config(args)
        assert config.tags == {"env": "prod"}

    def test_exits_without_resources_file(self):
        args = Namespace(resources_file=None, config_file=None)
        with pytest.raises(SystemExit):
            _build_config(args)

    @patch("cli.CoreConfig.from_yaml")
    def test_loads_from_config_file(self, mock_from_yaml):
        mock_from_yaml.return_value = CoreConfig(
            resources_file="r.json", output_file="o.xml",
        )
        args = _provision_args(config_file="/tmp/cfg.yaml")
        config = _build_config(args)
        mock_from_yaml.assert_called_once_with("/tmp/cfg.yaml")
        assert config.resources_file == "r.json"


class TestBuildTestCommand:
    def test_default_command(self):
        config = CoreConfig(resources_file="r.json", output_file="o.xml")
        cmd = _build_test_command(config)
        assert cmd.startswith("pytest test_suite/")
        assert "--junit-xml=/tmp/results.xml" in cmd

    def test_with_test_filter(self):
        config = CoreConfig(
            resources_file="r.json", output_file="o.xml",
            test_filter="test_ssh",
        )
        cmd = _build_test_command(config)
        assert "-k test_ssh" in cmd

    def test_with_markers(self):
        config = CoreConfig(
            resources_file="r.json", output_file="o.xml",
            include_markers="pub",
        )
        cmd = _build_test_command(config)
        assert "-m pub" in cmd

    def test_with_test_suites(self):
        config = CoreConfig(
            resources_file="r.json", output_file="o.xml",
            test_suites=["suite_a/", "suite_b/"],
        )
        cmd = _build_test_command(config)
        assert "suite_a/" in cmd
        assert "suite_b/" in cmd
        assert "test_suite/" not in cmd

    def test_with_parallel(self):
        config = CoreConfig(
            resources_file="r.json", output_file="o.xml",
            parallel=True,
        )
        cmd = _build_test_command(config)
        assert "-n auto" in cmd


class TestBuildParser:
    def test_provision_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["provision", "-r", "resources.json"])
        assert args.resources_file == "resources.json"
        assert args.debug is False

    def test_execute_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["execute", "--command", "echo hi"])
        assert args.command == "echo hi"
        assert args.timeout == 3600

    def test_collect_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["collect", "--results-dir", "/tmp/r", "-o", "out.xml"])
        assert args.results_dir == "/tmp/r"
        assert args.output_file == "out.xml"

    def test_run_subcommand_all_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "run", "-r", "resources.json", "-o", "out.xml",
            "-t", "test_ssh", "--test-suites", "a/", "b/",
            "-m", "pub", "-p", "-d", "-s", "-e", "automated",
            "--tags", "env:prod", "--command", "echo hi",
            "--timeout", "600", "-a",
        ])
        assert args.resources_file == "resources.json"
        assert args.test_filter == "test_ssh"
        assert args.test_suites == ["a/", "b/"]
        assert args.include_markers == "pub"
        assert args.parallel is True
        assert args.debug is True
        assert args.stop_cleanup is True
        assert args.environment == "automated"
        assert args.tags == "env:prod"
        assert args.command == "echo hi"
        assert args.timeout == 600
        assert args.attach is True

    def test_cleanup_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["cleanup", "-r", "resources.json"])
        assert args.resources_file == "resources.json"

    def test_execute_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["execute", "--command", "ls"])
        assert args.ssh_config == "/tmp/civ-ssh-config"
        assert args.instances_json == "/tmp/civ-instances.json"
        assert args.results_dir == "/tmp/civ-results"


class TestMain:
    def test_no_subcommand_returns_2(self):
        assert main([]) == 2

    @patch("cli.cmd_provision", return_value=0)
    def test_routes_to_provision(self, mock_cmd):
        result = main(["provision", "-r", "resources.json"])
        assert result == 0
        mock_cmd.assert_called_once()

    @patch("cli.cmd_execute", return_value=0)
    def test_routes_to_execute(self, mock_cmd):
        result = main(["execute", "--command", "echo hi"])
        assert result == 0

    @patch("cli.cmd_collect", return_value=0)
    def test_routes_to_collect(self, mock_cmd):
        result = main(["collect", "--results-dir", "/tmp/r", "-o", "out.xml"])
        assert result == 0

    @patch("cli.cmd_cleanup", return_value=0)
    def test_routes_to_cleanup(self, mock_cmd):
        result = main(["cleanup", "-r", "resources.json"])
        assert result == 0


class TestCmdProvision:
    @patch("cli.Provisioner")
    def test_returns_zero_on_success(self, MockProv):
        mock_prov = MockProv.return_value
        mock_prov.provision.return_value = {"inst1": MagicMock()}
        args = _provision_args()
        result = cmd_provision(args)
        assert result == 0
        mock_prov.provision.assert_called_once()
        mock_prov.prepare_environment.assert_called_once()


class TestCmdExecute:
    @patch("cli._load_instances")
    @patch("cli.execute")
    def test_returns_zero_on_all_passed(self, mock_execute, mock_load):
        mock_load.return_value = {"inst1": MagicMock()}
        mock_result = MagicMock()
        mock_result.all_passed = True
        mock_result.instance_results = [
            MagicMock(exit_code=0, instance_name="inst1"),
        ]
        mock_execute.return_value = mock_result
        args = Namespace(
            command="echo hi", ssh_config="/tmp/cfg",
            instances_json="/tmp/inst.json", results_dir="/tmp/r",
            timeout=3600,
        )
        assert cmd_execute(args) == 0

    @patch("cli._load_instances")
    @patch("cli.execute")
    def test_returns_one_on_failure(self, mock_execute, mock_load):
        mock_load.return_value = {"inst1": MagicMock()}
        mock_result = MagicMock()
        mock_result.all_passed = False
        mock_result.instance_results = [
            MagicMock(exit_code=1, instance_name="inst1"),
        ]
        mock_execute.return_value = mock_result
        args = Namespace(
            command="bad", ssh_config="/tmp/cfg",
            instances_json="/tmp/inst.json", results_dir="/tmp/r",
            timeout=3600,
        )
        assert cmd_execute(args) == 1


class TestCmdCollect:
    @patch("cli.merge_results")
    @patch("cli.glob.glob", return_value=["/tmp/r/a.xml", "/tmp/r/b.xml"])
    def test_returns_exit_code_from_results(self, mock_glob, mock_merge):
        mock_merge.return_value = MergeResult(
            total_tests=10, failures=0, errors=0, skipped=1, time=5.0,
        )
        args = Namespace(results_dir="/tmp/r", output_file="/tmp/out.xml")
        assert cmd_collect(args) == 0

    @patch("cli.merge_results")
    @patch("cli.glob.glob", return_value=["/tmp/r/a.xml"])
    def test_returns_one_on_failures(self, mock_glob, mock_merge):
        mock_merge.return_value = MergeResult(
            total_tests=10, failures=2, errors=0, skipped=0, time=5.0,
        )
        args = Namespace(results_dir="/tmp/r", output_file="/tmp/out.xml")
        assert cmd_collect(args) == 1

    @patch("cli.merge_results")
    @patch("cli.glob.glob", return_value=["/tmp/r/a.xml"])
    def test_returns_two_on_errors(self, mock_glob, mock_merge):
        mock_merge.return_value = MergeResult(
            total_tests=10, failures=0, errors=3, skipped=0, time=5.0,
        )
        args = Namespace(results_dir="/tmp/r", output_file="/tmp/out.xml")
        assert cmd_collect(args) == 2

    @patch("cli.glob.glob", return_value=[])
    def test_returns_two_when_no_files(self, mock_glob):
        args = Namespace(results_dir="/tmp/empty", output_file="/tmp/out.xml")
        assert cmd_collect(args) == 2


class TestCmdRun:
    @patch("cli.cmd_collect", return_value=0)
    @patch("cli.cmd_execute", return_value=0)
    @patch("cli.Provisioner")
    def test_full_pipeline_success(self, MockProv, mock_exec, mock_coll):
        mock_prov = MockProv.return_value
        mock_prov.provision.return_value = {"inst1": MagicMock()}

        args = _run_args()
        assert cmd_run(args) == 0
        mock_prov.provision.assert_called_once()
        mock_prov.prepare_environment.assert_called_once()
        mock_exec.assert_called_once()
        mock_coll.assert_called_once()
        mock_prov.cleanup.assert_called_once()

    @patch("cli.cmd_collect", return_value=1)
    @patch("cli.cmd_execute", return_value=0)
    @patch("cli.Provisioner")
    def test_returns_collect_exit_code(self, MockProv, mock_exec, mock_coll):
        mock_prov = MockProv.return_value
        mock_prov.provision.return_value = {"inst1": MagicMock()}

        args = _run_args()
        assert cmd_run(args) == 1

    @patch("cli.cmd_collect", return_value=0)
    @patch("cli.cmd_execute", return_value=1)
    @patch("cli.Provisioner")
    def test_returns_execute_exit_code_when_collect_passes(
        self, MockProv, mock_exec, mock_coll,
    ):
        mock_prov = MockProv.return_value
        mock_prov.provision.return_value = {"inst1": MagicMock()}

        args = _run_args()
        assert cmd_run(args) == 1

    @patch("cli.Provisioner")
    def test_returns_100_on_infra_error(self, MockProv):
        mock_prov = MockProv.return_value
        mock_prov.provision.side_effect = Exception("infra failed")

        args = _run_args()
        assert cmd_run(args) == 100
        mock_prov.cleanup.assert_called_once()

    @patch("cli.cmd_collect", return_value=0)
    @patch("cli.cmd_execute", return_value=0)
    @patch("cli.Provisioner")
    def test_skips_cleanup_when_stop_cleanup(self, MockProv, mock_exec, mock_coll):
        mock_prov = MockProv.return_value
        mock_prov.provision.return_value = {"inst1": MagicMock()}

        args = _run_args(stop_cleanup=True)
        cmd_run(args)
        mock_prov.cleanup.assert_not_called()

    @patch("cli.cmd_collect", return_value=0)
    @patch("cli.cmd_execute", return_value=0)
    @patch("cli.Provisioner")
    def test_passes_custom_command(self, MockProv, mock_exec, mock_coll):
        mock_prov = MockProv.return_value
        mock_prov.provision.return_value = {"inst1": MagicMock()}

        args = _run_args(command="echo hi")
        cmd_run(args)
        exec_call_args = mock_exec.call_args[0][0]
        assert exec_call_args.command == "echo hi"

    @patch("cli.cmd_collect", return_value=0)
    @patch("cli.cmd_execute", return_value=0)
    @patch("cli.write_instances_json")
    @patch("cli.Provisioner")
    def test_attach_skips_provision(self, MockProv, mock_write, mock_exec, mock_coll):
        mock_prov = MockProv.return_value
        mock_prov.get_instances.return_value = {"inst1": MagicMock()}

        args = _run_args(attach=True)
        assert cmd_run(args) == 0
        mock_prov.provision.assert_not_called()
        mock_prov.prepare_environment.assert_not_called()
        mock_prov.get_instances.assert_called_once()
        mock_write.assert_called_once()


class TestCmdCleanup:
    @patch("cli.Provisioner")
    def test_returns_zero(self, MockProv):
        mock_prov = MockProv.return_value
        args = Namespace(
            resources_file="resources.json", config_file=None,
            debug=False,
        )
        assert cmd_cleanup(args) == 0
        mock_prov.get_instances.assert_called_once()
        mock_prov.cleanup.assert_called_once()


class TestLoadInstances:
    def test_loads_from_json(self, tmp_path):
        data = {
            "inst1": {
                "name": "inst1", "address": "1.2.3.4",
                "username": "ec2-user", "cloud": "aws",
                "image": "ami-123",
            }
        }
        path = tmp_path / "instances.json"
        import json
        path.write_text(json.dumps(data))

        instances = _load_instances(str(path))
        assert "inst1" in instances
        assert instances["inst1"].address == "1.2.3.4"
