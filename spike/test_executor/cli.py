#!/usr/bin/env python3
"""CLI runner for YAML-based tests."""

import sys
import json
import argparse
from pathlib import Path
from typing import List
import time

from spike.test_executor.schema import YAMLTestParser
from spike.test_executor.executor import (
    TestExecutor, ExecutionContext, HostMetadata, HostInfoExtractor
)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Execute YAML-defined tests on a host"
    )
    parser.add_argument(
        '--test-file',
        '-t',
        required=True,
        help='Path to YAML test file to execute'
    )
    parser.add_argument(
        '--host',
        '-H',
        default='localhost',
        help='Remote hostname or IP (default: localhost for local execution)'
    )
    parser.add_argument(
        '--user',
        '-u',
        help='SSH user (if not specified, local execution is used)'
    )
    parser.add_argument(
        '--ssh-config',
        '-S',
        help='Path to SSH config file'
    )
    parser.add_argument(
        '--distro',
        '-d',
        help='Override distro detection (e.g., "rhel", "fedora")'
    )
    parser.add_argument(
        '--version',
        '-v',
        help='Override version detection (e.g., "9.3", "8.10")'
    )
    parser.add_argument(
        '--arch',
        help='Override arch detection (e.g., "x86_64", "aarch64")'
    )
    parser.add_argument(
        '--output',
        '-o',
        help='Output file path for JSON results (optional)'
    )
    parser.add_argument(
        '--step-timeout',
        type=int,
        default=0,
        help='Per-step command timeout in seconds (0 disables timeout)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--continue-on-failure',
        action='store_true',
        help='Execute all steps and report every failure instead of stopping at the first one'
    )
    
    return parser.parse_args()


def extract_host_metadata(args, context: ExecutionContext) -> HostMetadata:
    """Extract or override host metadata."""
    
    # If manual overrides provided, use those
    if args.distro and args.version and args.arch:
        return HostMetadata(
            distro=args.distro,
            version=args.version,
            arch=args.arch,
            hostname=args.host
        )
    
    # Otherwise, extract from host
    print("[INFO] Extracting host metadata...")
    extractor = HostInfoExtractor(context)
    metadata = extractor.extract_from_commands()
    
    # Override if specified
    if args.distro:
        metadata.distro = args.distro
    if args.version:
        metadata.version = args.version
    if args.arch:
        metadata.arch = args.arch
    
    return metadata


def _format_preview(text: str, limit: int = 240) -> str:
    """Format command output/error as a compact one-line preview."""
    if not text:
        return ""
    compact = " ".join(text.strip().split())
    if len(compact) <= limit:
        return compact
    return f"{compact[:limit]}..."


def print_test_result(result, verbose=False):
    """Print test result with grouped sections and summary statistics."""
    passed_steps = [s for s in result.steps if s.success and not s.skipped]
    failed_steps = [s for s in result.steps if not s.success]
    skipped_steps = [s for s in result.steps if s.skipped]
    total_steps = len(result.steps)
    pass_rate = (len(passed_steps) / total_steps * 100.0) if total_steps else 0.0

    status = "PASSED" if result.passed else "FAILED"
    print(f"\n=== Test Result: {result.test_name} ({result.test_id}) ===")
    print(f"Overall Status: {status}")
    if result.error_message:
        print(f"Reason: {result.error_message}")

    print(f"\nPassed Steps ({len(passed_steps)}):")
    if passed_steps:
        for step in passed_steps:
            print(f"  ✓ {step.step_name}")
    else:
        print("  (none)")

    print(f"\nFailed Steps ({len(failed_steps)}):")
    if failed_steps:
        for index, step in enumerate(failed_steps, start=1):
            print(f"  {index}. {step.step_name}")
            print(f"     action: {step.action}")
            print(f"     exit_code: {step.exit_code}")
            if step.error:
                print(f"     error: {_format_preview(step.error)}")
            if step.output:
                print(f"     output: {_format_preview(step.output)}")
            if not step.error and not step.output:
                print("     context: step returned failure without output/error text")
    else:
        print("  (none)")

    if verbose:
        print(f"\nSkipped Steps ({len(skipped_steps)}):")
        if skipped_steps:
            for step in skipped_steps:
                reason = _format_preview(step.output)
                print(f"  - {step.step_name}")
                if reason:
                    print(f"     reason: {reason}")
        else:
            print("  (none)")

    print("\nSummary:")
    print("+-----------+-------+")
    print(f"| total     | {total_steps:>5} |")
    print(f"| passed    | {len(passed_steps):>5} |")
    print(f"| failed    | {len(failed_steps):>5} |")
    print(f"| skipped   | {len(skipped_steps):>5} |")
    print(f"| pass_rate | {pass_rate:>5.1f}%|")
    print("+-----------+-------+")


def main():
    args = parse_arguments()
    
    # Load test
    print(f"[INFO] Loading test from: {args.test_file}")
    test = YAMLTestParser.load_from_file(args.test_file)
    print(f"[INFO] Loaded test: {test.name} ({test.test_id})")
    
    # Determine execution mode
    local_mode = (args.user is None)
    print(f"[INFO] Execution mode: {'LOCAL' if local_mode else 'SSH'}")
    
    # Create initial context
    context = ExecutionContext(
        host_metadata=HostMetadata(
            distro="unknown",
            version="unknown",
            arch="unknown",
            hostname=args.host
        ),
        variables={},
        ssh_config=args.ssh_config,
        user=args.user,
        hostname=args.host,
        local=local_mode,
        command_timeout_seconds=(args.step_timeout if args.step_timeout > 0 else None),
    )
    
    # Extract host metadata
    try:
        metadata = extract_host_metadata(args, context)
        context.host_metadata = metadata
        print(f"[INFO] Host metadata: {metadata.distro} {metadata.version} ({metadata.arch})")
    except Exception as e:
        print(f"[ERROR] Failed to extract host metadata: {e}", file=sys.stderr)
        if not args.verbose:
            return 1
        raise
    
    # Execute test
    print(f"[INFO] Executing test...")
    executor = TestExecutor(context)
    
    start_time = time.time()
    result = executor.execute_test(
        test,
        fail_fast=not args.continue_on_failure,
        progress=args.verbose,
    )
    elapsed = time.time() - start_time
    
    # Print results
    print_test_result(result, verbose=args.verbose)
    print(f"[INFO] Test completed in {elapsed:.2f} seconds")
    
    # Save output if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"[INFO] Results saved to: {args.output}")
    
    # Return exit code
    return 0 if result.passed else 1


if __name__ == '__main__':
    sys.exit(main())
