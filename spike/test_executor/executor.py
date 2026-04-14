"""Test executor engine for running YAML test definitions."""

import subprocess
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from packaging import version
from spike.test_executor.schema import YAMLTest, ExecutionStep, Condition


@dataclass
class HostMetadata:
    """Metadata about the target host."""
    distro: str
    version: str
    arch: str
    hostname: str 
    
    @property
    def distro_version(self) -> str:
        return f"{self.distro}{self.version.split('.')[0]}"


@dataclass
class ExecutionContext:
    """Execution context for a test run."""
    host_metadata: HostMetadata
    variables: Dict[str, str]
    ssh_config: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    local: bool = True
    command_timeout_seconds: Optional[int] = None


@dataclass
class StepResult:
    """Result of a single step execution."""
    step_name: str
    action: str
    success: bool
    output: str = ""
    error: str = ""
    exit_code: int = 0
    skipped: bool = False


@dataclass
class TestResult:
    """Result of complete test execution."""
    test_id: str
    test_name: str
    passed: bool
    steps: List[StepResult]
    error_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'test_id': self.test_id,
            'name': self.test_name,
            'passed': self.passed,
            'error': self.error_message,
            'steps': [
                {
                    'name': s.step_name,
                    'action': s.action,
                    'success': s.success,
                    'skipped': s.skipped,
                    'output': s.output,
                    'error': s.error,
                    'exit_code': s.exit_code
                } for s in self.steps
            ]
        }


class HostInfoExtractor:
    """Extracts host metadata for condition evaluation."""
    
    def __init__(self, context: ExecutionContext):
        self.context = context
    
    def extract_from_commands(self) -> HostMetadata:
        """Extract host metadata by running remote commands."""
        distro = self._run_cmd("grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '\"'").strip()
        version_str = self._run_cmd("grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '\"'").strip()
        arch = self._run_cmd("uname -m").strip()
        hostname = self._run_cmd("hostname").strip()
        
        return HostMetadata(
            distro=distro,
            version=version_str,
            arch=arch,
            hostname=hostname
        )
    
    def _run_cmd(self, cmd: str) -> str:
        """Run command and return output."""
        if self.context.local:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        else:
            # SSH execution
            ssh_cmd = self._build_ssh_command(cmd)
            result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True)
            return result.stdout


class ConditionEvaluator:
    """Evaluates whether a test should run on a given host."""
    
    @staticmethod
    def should_run_test(condition: Condition, host_metadata: HostMetadata) -> Tuple[bool, str]:
        """
        Determine if test should run on this host.
        Returns: (should_run, reason)
        """
        # Check exclude_on first
        if condition.exclude_on:
            for exclude_pattern in condition.exclude_on:
                if ConditionEvaluator._matches_pattern(exclude_pattern, host_metadata):
                    return (False, f"Excluded by pattern: {exclude_pattern}")
        
        # Check run_on
        if condition.run_on:
            if 'all' in condition.run_on:
                return (True, "Matches 'all'")
            
            for run_pattern in condition.run_on:
                if ConditionEvaluator._matches_pattern(run_pattern, host_metadata):
                    return (True, f"Matches pattern: {run_pattern}")
            
            return (False, f"Does not match any run_on pattern: {condition.run_on}")
        
        return (True, "No conditions specified")
    
    @staticmethod
    def _matches_pattern(pattern: str, host_metadata: HostMetadata) -> bool:
        """Check if a pattern matches the host metadata."""
        match = re.match(r'([a-z]+)(>=|<=|>|<|==)?(.+)?', pattern)
        if not match:
            return False
        
        pattern_distro = match.group(1)
        operator = match.group(2)
        pattern_version = match.group(3)
        
        if pattern_distro != host_metadata.distro:
            return False
        
        if not operator or not pattern_version:
            return True
        
        try:
            host_ver = version.parse(host_metadata.version)
            pattern_ver = version.parse(pattern_version)
            
            if operator == '>=':
                return host_ver >= pattern_ver
            elif operator == '<=':
                return host_ver <= pattern_ver
            elif operator == '>':
                return host_ver > pattern_ver
            elif operator == '<':
                return host_ver < pattern_ver
            elif operator == '==':
                return host_ver == pattern_ver
        except Exception:
            return False
        
        return False


class StepExecutor:
    """Executes individual test steps."""
    
    def __init__(self, context: ExecutionContext):
        self.context = context
    
    def execute_step(self, step: ExecutionStep) -> StepResult:
        """Execute a single step and return result."""
        result = StepResult(
            step_name=step.name or step.action,
            action=step.action,
            success=False
        )
        
        try:
                # Per-step condition gate. skip without failing
                if step.conditions is not None:
                    should_run, reason = ConditionEvaluator.should_run_test(
                        step.conditions, self.context.host_metadata
                    )
                    if not should_run:
                        result.success = True
                        result.skipped = True
                        result.output = f"Skipped: {reason}"
                        return result

                if step.action == 'run_command':
                    self._execute_run_command(step, result)
                elif step.action == 'check_file':
                    self._execute_check_file(step, result)
                elif step.action == 'check_file_content':
                    self._execute_check_file_content(step, result)
                elif step.action == 'assert_command_exit_code':
                    self._execute_assert_command_exit_code(step, result)
                elif step.action == 'compare_file_with_local':
                    self._execute_compare_file_with_local(step, result)
                elif step.action == 'check_service':
                    self._execute_check_service(step, result)
                elif step.action == 'check_package':
                    self._execute_check_package(step, result)
                elif step.action == 'check_user':
                    self._execute_check_user(step, result)
                elif step.action == 'check_command_output':
                    self._execute_check_command_output(step, result)
                else:
                    result.error = f"Unknown action: {step.action}"
        except Exception as e:
            result.error = str(e)
            result.success = False
        
        return result
    
    def _execute_run_command(self, step: ExecutionStep, result: StepResult) -> None:
        """Execute run_command action."""
        output, exit_code = self._run_remote_command(step.command)
        result.output = output
        result.exit_code = exit_code
        result.success = exit_code == 0
        
        if step.store_as:
            self.context.variables[step.store_as] = output.strip()
    
    def _execute_check_file(self, step: ExecutionStep, result: StepResult) -> None:
        """Execute check_file action."""
        if step.operator == 'exists':
            output, exit_code = self._run_remote_command(f"ls -la {step.path} 2>&1")
            result.success = exit_code == 0
            result.output = output if result.success else "File does not exist"
        elif step.operator == 'not_exists':
            output, exit_code = self._run_remote_command(f"ls -la {step.path} 2>&1")
            result.success = exit_code != 0
            result.output = "File does not exist" if result.success else output
        elif step.operator == 'linked_to':
            output, exit_code = self._run_remote_command(f"readlink -f {step.path} 2>&1")
            resolved = output.strip()
            result.success = exit_code == 0 and resolved == step.expected
            result.output = f"Symlink resolves to: {resolved!r}, expected: {step.expected!r}"
        elif step.operator == 'mode':
            output, exit_code = self._run_remote_command(f"stat -c '%a' {step.path} 2>&1")
            actual_mode = output.strip()
            result.success = exit_code == 0 and actual_mode == str(step.expected)
            result.output = f"File mode: {actual_mode!r}, expected: {step.expected!r}"
        else:
            raise ValueError(f"Unknown file operator: {step.operator}")
    
    def _execute_check_file_content(self, step: ExecutionStep, result: StepResult) -> None:
        """Execute check_file_content action."""
        cat_cmd = f"cat {step.path} 2>/dev/null || echo ''"
        output, _ = self._run_remote_command(cat_cmd)
        
        if step.operator == 'empty':
            result.success = len(output.strip()) == 0
            result.output = f"File content length: {len(output.strip())}"
        elif step.operator == 'not_empty':
            result.success = len(output.strip()) > 0
            result.output = f"File content length: {len(output.strip())}"
        elif step.operator == 'contains':
            result.success = step.expected in output
            result.output = output[:200] if output else "(empty)"
        elif step.operator == 'not_contains':
            result.success = step.expected not in output
            result.output = output[:200] if output else "(empty)"
        else:
            raise ValueError(f"Unknown content operator: {step.operator}")
    
    def _execute_assert_command_exit_code(self, step: ExecutionStep, result: StepResult) -> None:
        """Execute assert_command_exit_code action."""
        output, exit_code = self._run_remote_command(step.command)
        result.output = output
        result.exit_code = exit_code
        result.success = exit_code == step.expected

    def _execute_compare_file_with_local(self, step: ExecutionStep, result: StepResult) -> None:
        """Compare a remote file's content against a local reference file."""
        local_path = step.params.get('local_path') if step.params else None
        if local_path is None:
            result.error = "compare_file_with_local requires params.local_path"
            return

        try:
            with open(local_path, 'r') as fh:
                local_content = fh.read()
        except OSError as exc:
            result.error = f"Cannot read local reference file '{local_path}': {exc}"
            return

        remote_content, exit_code = self._run_remote_command(f"cat {step.path} 2>/dev/null")
        if exit_code != 0:
            result.success = False
            result.error = f"Remote file '{step.path}' not found or not readable"
            return

        result.success = local_content.strip() == remote_content.strip()
        if not result.success:
            result.output = (
                f"Files differ.\n"
                f"  local ({local_path}): {local_content[:200]!r}\n"
                f"  remote ({step.path}): {remote_content[:200]!r}"
            )

    def _execute_check_service(self, step: ExecutionStep, result: StepResult) -> None:
        """Check systemd service state."""
        svc = step.service
        if step.operator in ('is_running', 'is_active'):
            _, rc = self._run_remote_command(f"systemctl is-active {svc}")
            result.success = rc == 0
            result.output = f"Service {svc} is {'active' if result.success else 'not active'}"
        elif step.operator == 'is_enabled':
            _, rc = self._run_remote_command(f"systemctl is-enabled {svc}")
            result.success = rc == 0
            result.output = f"Service {svc} is {'enabled' if result.success else 'not enabled'}"
        elif step.operator == 'not_running':
            _, rc = self._run_remote_command(f"systemctl is-active {svc}")
            result.success = rc != 0
            result.output = f"Service {svc} is {'not active (expected)' if result.success else 'active (unexpected)'}"
        elif step.operator == 'not_enabled':
            _, rc = self._run_remote_command(f"systemctl is-enabled {svc}")
            result.success = rc != 0
            result.output = f"Service {svc} is {'not enabled (expected)' if result.success else 'enabled (unexpected)'}"
        else:
            raise ValueError(f"Unknown service operator: {step.operator}")

    def _execute_check_package(self, step: ExecutionStep, result: StepResult) -> None:
        """Check RPM package state."""
        pkg = step.package
        if step.operator == 'is_installed':
            _, rc = self._run_remote_command(f"rpm -q {pkg}")
            result.success = rc == 0
            result.output = f"Package {pkg} is {'installed' if result.success else 'not installed'}"
        elif step.operator == 'not_installed':
            _, rc = self._run_remote_command(f"rpm -q {pkg}")
            result.success = rc != 0
            result.output = f"Package {pkg} is {'not installed (expected)' if result.success else 'installed (unexpected)'}"
        else:
            raise ValueError(f"Unknown package operator: {step.operator}")

    def _execute_check_user(self, step: ExecutionStep, result: StepResult) -> None:
        """Check OS user existence."""
        user = step.user
        _, rc = self._run_remote_command(f"id '{user}' 2>/dev/null")
        if step.operator == 'exists':
            result.success = rc == 0
            result.output = f"User '{user}' {'exists' if result.success else 'does not exist'}"
        elif step.operator == 'not_exists':
            result.success = rc != 0
            result.output = f"User '{user}' {'does not exist (expected)' if result.success else 'exists (unexpected)'}"
        else:
            raise ValueError(f"Unknown user operator: {step.operator}")

    def _execute_check_command_output(self, step: ExecutionStep, result: StepResult) -> None:
        """Run a command and assert its stdout against an expected value."""
        output, _ = self._run_remote_command(step.command)
        value = output.strip()
        result.output = value[:200]
        expected = str(step.expected) if step.expected is not None else ""
        if step.operator == 'equals':
            result.success = value == expected
        elif step.operator == 'contains':
            result.success = expected in value
        elif step.operator == 'not_contains':
            result.success = expected not in value
        elif step.operator == 'not_empty':
            result.success = len(value) > 0
        elif step.operator == 'empty':
            result.success = len(value) == 0
        else:
            raise ValueError(f"Unknown command output operator: {step.operator}")
    
    def _run_remote_command(self, cmd: str) -> Tuple[str, int]:
        """Run command on remote host or locally."""
        if self.context.local:
            return self._run_local_command(cmd)
        else:
            return self._run_ssh_command(cmd)
    
    def _run_local_command(self, cmd: str) -> Tuple[str, int]:
        """Run command locally."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.context.command_timeout_seconds,
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            timeout = self.context.command_timeout_seconds
            return f"Command timed out after {timeout}s: {cmd}", 124
    
    def _run_ssh_command(self, cmd: str) -> Tuple[str, int]:
        """Run command via SSH."""
        ssh_cmd = f"ssh {self.context.user}@{self.context.hostname} '{cmd}'"
        if self.context.ssh_config:
            ssh_cmd = f"ssh -F {self.context.ssh_config} {self.context.user}@{self.context.hostname} '{cmd}'"

        try:
            result = subprocess.run(
                ssh_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.context.command_timeout_seconds,
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            timeout = self.context.command_timeout_seconds
            return f"SSH command timed out after {timeout}s: {cmd}", 124


class TestExecutor:
    """Main test executor - orchestrates test execution."""
    
    def __init__(self, context: ExecutionContext):
        self.context = context
        self.condition_evaluator = ConditionEvaluator()
        self.step_executor = StepExecutor(context)
    
    def execute_test(self, test: YAMLTest, fail_fast: bool = True, progress: bool = False) -> TestResult:
        """Execute a complete test and return result."""
        result = TestResult(
            test_id=test.test_id,
            test_name=test.name,
            passed=False,
            steps=[]
        )
        
        should_run, reason = self.condition_evaluator.should_run_test(
            test.conditions,
            self.context.host_metadata
        )
        
        if not should_run:
            result.error_message = f"Test skipped: {reason}"
            result.passed = True
            return result
        
        if test.conditions.wait_seconds and test.conditions.wait_seconds > 0:
            import time
            print(f"Waiting {test.conditions.wait_seconds} seconds before running test...")
            time.sleep(test.conditions.wait_seconds)
        
        failed_steps = []
        total_steps = len(test.steps)
        for index, step in enumerate(test.steps, start=1):
            if progress:
                print(f"[STEP {index}/{total_steps}] Running: {step.name or step.action}")

            step_result = self.step_executor.execute_step(step)
            result.steps.append(step_result)

            if progress:
                if step_result.skipped:
                    state = "SKIP"
                elif step_result.success:
                    state = "PASS"
                else:
                    state = "FAIL"
                print(f"[STEP {index}/{total_steps}] {state}: {step_result.step_name}")
            
            if not step_result.success:
                if step_result.skipped:
                    continue
                failed_steps.append(step_result)
                if fail_fast:
                    result.passed = False
                    result.error_message = (
                        f"Step '{step_result.step_name}' failed: "
                        f"{step_result.error or step_result.output or 'step failed'}"
                    )
                    break

        if not failed_steps:
            result.passed = True
        elif not fail_fast:
            result.passed = False
            failed_names = ", ".join(f"'{step.step_name}'" for step in failed_steps)
            result.error_message = (
                f"{len(failed_steps)} step(s) failed: {failed_names}"
            )
        
        return result
