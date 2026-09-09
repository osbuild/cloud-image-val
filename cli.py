#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from core.config import CoreConfig
from core.executor import execute
from core.metadata import InstanceMetadata, write_instances_json
from core.provisioner import Provisioner
from core.results import get_exit_code, merge_results


def _parse_tags(tags_str: str) -> dict[str, str]:
    result = {}
    for pair in tags_str.split(","):
        pair = pair.strip()
        if ":" in pair:
            key, value = pair.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def _build_config(args: argparse.Namespace) -> CoreConfig:
    if getattr(args, "config_file", None):
        return CoreConfig.from_yaml(args.config_file)

    resources_file = getattr(args, "resources_file", None)
    if not resources_file:
        raise SystemExit("error: --resources-file is required (or use --config-file)")

    config_dict: dict[str, object] = {
        "resources_file": resources_file,
        "output_file": getattr(args, "output_file", None) or "/tmp/civ-results.xml",
    }

    for attr in ("debug", "parallel", "stop_cleanup"):
        val = getattr(args, attr, None)
        if val is not None:
            config_dict[attr] = val

    if getattr(args, "tags", None):
        config_dict["tags"] = _parse_tags(args.tags)

    if getattr(args, "environment", None):
        config_dict["environment"] = args.environment

    for attr in ("test_filter", "test_suites", "include_markers"):
        val = getattr(args, attr, None)
        if val is not None:
            config_dict[attr] = val

    return CoreConfig.from_dict(config_dict)


def _load_instances(path: str) -> dict[str, InstanceMetadata]:
    with open(path) as f:
        data = json.load(f)
    return {
        key: InstanceMetadata.from_dict(inst_data)
        for key, inst_data in data.items()
    }


def _build_test_command(config: CoreConfig) -> str:
    parts = ["pytest"]
    if config.test_suites:
        parts.extend(config.test_suites)
    else:
        parts.append("test_suite/")
    parts.append("--junit-xml=/tmp/results.xml")
    if config.test_filter:
        parts.extend(["-k", config.test_filter])
    if config.include_markers:
        parts.extend(["-m", config.include_markers])
    if config.parallel:
        parts.extend(["-n", "auto"])
    return " ".join(parts)


def cmd_provision(args: argparse.Namespace) -> int:
    config = _build_config(args)
    provisioner = Provisioner(config)
    instances = provisioner.provision()
    provisioner.prepare_environment(instances)
    print(f"Provisioned {len(instances)} instance(s)")
    return 0


def cmd_execute(args: argparse.Namespace) -> int:
    instances = _load_instances(args.instances_json)
    result = execute(
        instances=instances,
        command=args.command,
        ssh_config=args.ssh_config,
        results_dir=args.results_dir,
        timeout=args.timeout,
    )
    for ir in result.instance_results:
        status = "PASS" if ir.exit_code == 0 else "FAIL"
        print(f"  [{status}] {ir.instance_name} (exit={ir.exit_code})")
    return 0 if result.all_passed else 1


def cmd_collect(args: argparse.Namespace) -> int:
    result_files = sorted(glob.glob(os.path.join(args.results_dir, "*.xml")))
    if not result_files:
        print(f"No XML result files found in {args.results_dir}")
        return 2
    merge_result = merge_results(result_files, args.output_file)
    print(
        f"Merged {merge_result.total_tests} tests: "
        f"{merge_result.failures} failures, "
        f"{merge_result.errors} errors, "
        f"{merge_result.skipped} skipped"
    )
    return get_exit_code(merge_result)


def cmd_run(args: argparse.Namespace) -> int:
    config = _build_config(args)
    provisioner = Provisioner(config)
    try:
        if getattr(args, "attach", False):
            instances = provisioner.get_instances()
            write_instances_json(instances, config.instances_json)
        else:
            instances = provisioner.provision()
            provisioner.prepare_environment(instances)

        command = getattr(args, "command", None) or _build_test_command(config)
        results_dir = os.path.dirname(config.output_file) or "/tmp"

        exec_args = argparse.Namespace(
            instances_json=config.instances_json,
            command=command,
            ssh_config=config.ssh_config_file,
            results_dir=results_dir,
            timeout=getattr(args, "timeout", 3600),
        )
        exit_code = cmd_execute(exec_args)

        collect_args = argparse.Namespace(
            results_dir=results_dir,
            output_file=config.output_file,
        )
        collect_code = cmd_collect(collect_args)

        return collect_code if collect_code != 0 else exit_code

    except Exception as exc:
        print(f"Error: {exc}")
        return 100
    finally:
        if not config.stop_cleanup:
            provisioner.cleanup()


def cmd_cleanup(args: argparse.Namespace) -> int:
    config = _build_config(args)
    provisioner = Provisioner(config)
    provisioner.get_instances()
    provisioner.cleanup()
    print("Cleanup complete")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="civ",
        description="Cloud Image Validator - phase-based CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # --- provision ---
    p_prov = subparsers.add_parser("provision", help="Provision cloud instances")
    p_prov.add_argument("-r", "--resources-file",
                        help="Path to resources JSON file")
    p_prov.add_argument("-c", "--config-file", default=None,
                        help="Path to YAML config file")
    p_prov.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debug mode")
    p_prov.add_argument("--tags", default=None,
                        help="Tags as 'key1:value1, key2:value2'")
    p_prov.add_argument("-p", "--parallel", action="store_true", default=False,
                        help="Enable parallel mode")
    p_prov.set_defaults(func=cmd_provision)

    # --- execute ---
    p_exec = subparsers.add_parser(
        "execute", help="Run a command on provisioned instances",
    )
    p_exec.add_argument("--command", required=True,
                        help="Command to execute on instances")
    p_exec.add_argument("--ssh-config", default="/tmp/civ-ssh-config",
                        help="Path to SSH config file")
    p_exec.add_argument("--instances-json", default="/tmp/civ-instances.json",
                        help="Path to instances JSON file")
    p_exec.add_argument("--results-dir", default="/tmp/civ-results",
                        help="Directory to store result files")
    p_exec.add_argument("--timeout", type=int, default=3600,
                        help="Timeout in seconds (default: 3600)")
    p_exec.set_defaults(func=cmd_execute)

    # --- collect ---
    p_coll = subparsers.add_parser(
        "collect", help="Validate and merge JUnit XML results",
    )
    p_coll.add_argument("--results-dir", required=True,
                        help="Directory containing XML result files")
    p_coll.add_argument("-o", "--output-file", required=True,
                        help="Output path for merged JUnit XML")
    p_coll.set_defaults(func=cmd_collect)

    # --- run ---
    p_run = subparsers.add_parser(
        "run", help="Full pipeline: provision -> execute -> collect -> cleanup",
    )
    p_run.add_argument("-r", "--resources-file",
                       help="Path to resources JSON file")
    p_run.add_argument("-o", "--output-file", default=None,
                       help="Output file path for test results")
    p_run.add_argument("-t", "--test-filter", default=None,
                       help="Filter tests by name")
    p_run.add_argument("--test-suites", nargs="+", default=None,
                       help="Test suite paths")
    p_run.add_argument("-m", "--include-markers", default=None,
                       help="Pytest markers expression")
    p_run.add_argument("-p", "--parallel", action="store_true", default=False,
                       help="Enable parallel test execution")
    p_run.add_argument("-d", "--debug", action="store_true", default=False,
                       help="Enable debug mode")
    p_run.add_argument("-s", "--stop-cleanup", action="store_true", default=False,
                       help="Skip cleanup after execution")
    p_run.add_argument("-e", "--environment", default=None,
                       help="Environment: 'local' or 'automated'")
    p_run.add_argument("-c", "--config-file", default=None,
                       help="Path to YAML config file")
    p_run.add_argument("--tags", default=None,
                       help="Tags as 'key1:value1, key2:value2'")
    p_run.add_argument("--command", default=None,
                       help="Custom command (overrides test flags)")
    p_run.add_argument("--timeout", type=int, default=3600,
                       help="Timeout in seconds (default: 3600)")
    p_run.add_argument("-a", "--attach", action="store_true", default=False,
                       help="Attach to existing infrastructure instead of provisioning")
    p_run.set_defaults(func=cmd_run)

    # --- cleanup ---
    p_clean = subparsers.add_parser(
        "cleanup", help="Destroy provisioned infrastructure",
    )
    p_clean.add_argument("-r", "--resources-file",
                         help="Path to resources JSON file")
    p_clean.add_argument("-c", "--config-file", default=None,
                         help="Path to YAML config file")
    p_clean.add_argument("-d", "--debug", action="store_true", default=False,
                         help="Enable debug mode")
    p_clean.set_defaults(func=cmd_cleanup)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
