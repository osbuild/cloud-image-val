"""YAML Test Runner - Adapter between spike executor and CloudImageValidator."""

import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from spike.test_executor.executor import (
    TestExecutor, ExecutionContext, HostMetadata, HostInfoExtractor
)
from spike.test_executor.schema import YAMLTestParser


class YAMLTestRunner:
    """Executes YAML-based tests across multiple cloud instances."""
    
    def __init__(self,
                 cloud_provider: str,
                 instances: dict,
                 ssh_config: str,
                 parallel: bool = True,
                 debug: bool = False):
        """
        Initialize YAML test runner.
        
        Args:
            cloud_provider: Cloud provider name (aws, azure, gcloud)
            instances: Dict of instance info {name: {username, address, ...}}
            ssh_config: Path to SSH config file
            parallel: Enable parallel test execution
            debug: Enable debug output
        """
        self.cloud_provider = cloud_provider
        self.instances = instances
        self.ssh_config = ssh_config
        self.parallel = parallel
        self.debug = debug
        self.test_results = []
    
    def run_tests(self,
                  yaml_test_paths: List[str],
                  output_filepath: str,
                  test_filter: Optional[str] = None,
                  include_tags: Optional[List[str]] = None) -> int:
        """
        Execute YAML tests on all instances.
        
        Args:
            yaml_test_paths: List of .yaml test file paths
            output_filepath: Path to save results (JUnit XML format)
            test_filter: Filter tests by ID substring
            include_tags: Only run tests with these tags
            
        Returns:
            Exit code: 0 if all tests passed, 1 if any failed, >1 for errors
        """
        self.test_results = []
        
        if self.debug:
            print(f"[DEBUG] YAML Test Runner initialized")
            print(f"[DEBUG] Cloud provider: {self.cloud_provider}")
            print(f"[DEBUG] Instances: {len(self.instances)}")
            print(f"[DEBUG] YAML tests: {len(yaml_test_paths)}")
        
        for instance_name, instance_info in self.instances.items():
            print(f"\n{'='*70}")
            print(f"Testing instance: {instance_name}")
            print(f"{'='*70}")
            
            host_metadata = self._extract_host_metadata(instance_info)
            print(f"Detected: {host_metadata.distro} {host_metadata.version} ({host_metadata.arch})")
            
            for yaml_test_path in yaml_test_paths:
                if test_filter and test_filter not in yaml_test_path:
                    continue
                
                self._run_test_on_instance(
                    yaml_test_path,
                    instance_info,
                    host_metadata,
                    include_tags
                )
        
        self._write_results_junit_xml(output_filepath)
        self._write_results_json(output_filepath.replace('.xml', '.json'))
        
        failed_count = sum(1 for r in self.test_results if not r['passed'])
        if failed_count > 0:
            print(f"\n⚠ {failed_count} test(s) failed")
            return 1
        else:
            print(f"\n✓ All {len(self.test_results)} test(s) passed")
            return 0
    
    def _extract_host_metadata(self, instance_info: dict) -> HostMetadata:
        """Extract host metadata by running remote commands."""
        context = ExecutionContext(
            host_metadata=HostMetadata(
                distro="unknown",
                version="unknown",
                arch="unknown",
                hostname=instance_info['address']
            ),
            variables={},
            ssh_config=self.ssh_config,
            user=instance_info['username'],
            hostname=instance_info['address'],
            local=False
        )
        
        try:
            extractor = HostInfoExtractor(context)
            return extractor.extract_from_commands()
        except Exception as e:
            print(f"[WARN] Failed to extract host metadata: {e}")
            return HostMetadata(
                distro="unknown",
                version="0.0",
                arch="unknown",
                hostname=instance_info['address']
            )
    
    def _run_test_on_instance(self,
                             yaml_test_path: str,
                             instance_info: dict,
                             host_metadata: HostMetadata,
                             include_tags: Optional[List[str]] = None) -> None:
        """Run a single YAML test on an instance."""
        try:
            test = YAMLTestParser.load_from_file(yaml_test_path)
            
            if include_tags:
                if not any(tag in (test.tags or []) for tag in include_tags):
                    if self.debug:
                        print(f"  [SKIP] {test.test_id} - tags not in {include_tags}")
                    return
            
            context = ExecutionContext(
                host_metadata=host_metadata,
                variables={},
                ssh_config=self.ssh_config,
                user=instance_info['username'],
                hostname=instance_info['address'],
                local=False
            )
            
            executor = TestExecutor(context)
            result = executor.execute_test(test)
            
            test_result = {
                'test_id': test.test_id,
                'name': test.name,
                'instance': instance_info['name'],
                'hostname': instance_info['address'],
                'passed': result.passed,
                'error_message': result.error_message,
                'steps': [s.to_dict() if hasattr(s, 'to_dict') else 
                         {'name': s.step_name, 'success': s.success, 'error': s.error}
                         for s in result.steps],
                'duration_seconds': 0,
                'timestamp': datetime.now().isoformat()
            }
            self.test_results.append(test_result)
            
            status = "❤" if result.passed else "☠"
            print(f"{status} {test.test_id}: {test.name}")
            if not result.passed:
                print(f"  Error: {result.error_message}")
            
        except Exception as e:
            print(f"✗ {yaml_test_path}: Exception: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            
            self.test_results.append({
                'test_id': Path(yaml_test_path).stem,
                'name': Path(yaml_test_path).name,
                'instance': instance_info['name'],
                'hostname': instance_info['address'],
                'passed': False,
                'error_message': str(e),
                'steps': [],
                'timestamp': datetime.now().isoformat()
            })
    
    def _write_results_junit_xml(self, output_filepath: str) -> None:
        """Write test results in JUnit XML format (compatible with pytest)."""
        os.makedirs(os.path.dirname(output_filepath) or '.', exist_ok=True)
        
        total_tests = len(self.test_results)
        failed_tests = sum(1 for r in self.test_results if not r['passed'])
        
        xml_lines = [
            '<?xml version="1.0" encoding="utf-8"?>',
            f'<testsuites tests="{total_tests}" failures="{failed_tests}" errors="0">',
            f'  <testsuite name="yaml-tests" tests="{total_tests}" failures="{failed_tests}" errors="0">',
        ]
        
        for result in self.test_results:
            test_name = f"{result['instance']}::{result['test_id']}"
            xml_lines.append(f'    <testcase classname="yaml_tests" name="{test_name}">')
            
            if not result['passed']:
                xml_lines.append(f'      <failure message="{self._escape_xml(result["error_message"])}"/>')
            
            xml_lines.append('    </testcase>')
        
        xml_lines.extend([
            '  </testsuite>',
            '</testsuites>'
        ])
        
        with open(output_filepath, 'w') as f:
            f.write('\n'.join(xml_lines))
        
        print(f"\n[INFO] JUnit XML results saved to: {output_filepath}")
    
    def _write_results_json(self, output_filepath: str) -> None:
        """Write test results in JSON format."""
        os.makedirs(os.path.dirname(output_filepath) or '.', exist_ok=True)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'total': len(self.test_results),
            'passed': sum(1 for r in self.test_results if r['passed']),
            'failed': sum(1 for r in self.test_results if not r['passed']),
            'tests': self.test_results
        }
        
        with open(output_filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[INFO] JSON results saved to: {output_filepath}")
    
    @staticmethod
    def _escape_xml(text: str) -> str:
        """Escape special XML characters."""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&apos;'))
