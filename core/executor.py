from __future__ import annotations

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from core.metadata import InstanceMetadata


@dataclass
class InstanceResult:
    instance_name: str
    exit_code: int
    result_file: str | None
    stdout: str
    stderr: str


@dataclass
class ExecutionResult:
    instance_results: list[InstanceResult]

    @property
    def all_passed(self) -> bool:
        return all(r.exit_code == 0 for r in self.instance_results)


def _run_on_instance(
    instance: InstanceMetadata,
    command: str,
    ssh_config: str,
    results_dir: str,
    remote_results_path: str,
    timeout: int,
) -> InstanceResult:
    try:
        result = subprocess.run(
            [
                "ssh",
                "-F", ssh_config,
                f"{instance.username}@{instance.address}",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        exit_code = 124
        stdout = ""
        stderr = f"SSH command timed out after {timeout} seconds"
    except Exception as exc:
        exit_code = 1
        stdout = ""
        stderr = str(exc)

    local_result_file = os.path.join(
        results_dir, f"instance-{instance.name}.xml",
    )
    try:
        scp_result = subprocess.run(
            [
                "scp",
                "-F", ssh_config,
                f"{instance.username}@{instance.address}:{remote_results_path}",
                local_result_file,
            ],
            capture_output=True,
            timeout=60,
        )
        collected = scp_result.returncode == 0
    except Exception:
        collected = False

    return InstanceResult(
        instance_name=instance.name,
        exit_code=exit_code,
        result_file=local_result_file if collected else None,
        stdout=stdout,
        stderr=stderr,
    )


def execute(
    instances: dict[str, InstanceMetadata],
    command: str,
    ssh_config: str,
    results_dir: str,
    timeout: int = 3600,
    remote_results_path: str = "/tmp/results.xml",
) -> ExecutionResult:
    os.makedirs(results_dir, exist_ok=True)

    results: list[InstanceResult] = []
    with ThreadPoolExecutor(max_workers=len(instances) or 1) as pool:
        futures = {
            pool.submit(
                _run_on_instance,
                instance=inst,
                command=command,
                ssh_config=ssh_config,
                results_dir=results_dir,
                remote_results_path=remote_results_path,
                timeout=timeout,
            ): key
            for key, inst in instances.items()
        }

        for future in as_completed(futures):
            results.append(future.result())

    return ExecutionResult(instance_results=results)
