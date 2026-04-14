"""YAML Test Definition Schema and Validators."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import yaml


@dataclass
class Condition:
    """Represents a test execution condition (run_on, exclude_on, etc)."""
    run_on: Optional[List[str]] = None
    exclude_on: Optional[List[str]] = None
    wait_seconds: Optional[int] = None


@dataclass
class ExecutionStep:
    """Represents a single test execution step."""
    action: str
    name: Optional[str] = None
    command: Optional[str] = None
    path: Optional[str] = None
    operator: Optional[str] = None
    expected: Optional[Any] = None
    store_as: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    service: Optional[str] = None
    package: Optional[str] = None
    user: Optional[str] = None
    conditions: Optional[Condition] = None

    def __post_init__(self):
        if self.params is None:
            self.params = {}


@dataclass
class YAMLTest:
    """Represents a complete YAML test definition."""
    test_id: str
    name: str
    description: str
    conditions: Condition
    steps: List[ExecutionStep]
    tags: Optional[List[str]] = None


class YAMLTestParser:
    """Parser for YAML test definitions."""

    @staticmethod
    def load_from_file(filepath: str) -> YAMLTest:
        """Load and parse a YAML test file."""
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        return YAMLTestParser.parse(data)

    @staticmethod
    def parse(data: Dict[str, Any]) -> YAMLTest:
        """Parse a YAML test dictionary into YAMLTest object."""
        conditions_data = data.get('conditions', {})
        conditions = Condition(
            run_on=conditions_data.get('run_on', ['all']),
            exclude_on=conditions_data.get('exclude_on'),
            wait_seconds=conditions_data.get('wait_seconds', 0)
        )

        steps_data = data.get('steps', [])
        steps = [YAMLTestParser._parse_step(step) for step in steps_data]

        return YAMLTest(
            test_id=data.get('test_id'),
            name=data.get('name'),
            description=data.get('description'),
            conditions=conditions,
            steps=steps,
            tags=data.get('tags', [])
        )

    @staticmethod
    def _parse_step(step_data: Dict[str, Any]) -> ExecutionStep:
        """Parse a single execution step."""
        step_conditions = None
        if 'conditions' in step_data:
            cdata = step_data['conditions']
            step_conditions = Condition(
                run_on=cdata.get('run_on'),
                exclude_on=cdata.get('exclude_on'),
            )
        return ExecutionStep(
            action=step_data.get('action'),
            name=step_data.get('name'),
            command=step_data.get('command'),
            path=step_data.get('path'),
            operator=step_data.get('operator'),
            expected=step_data.get('expected'),
            store_as=step_data.get('store_as'),
            params=step_data.get('params', {}),
            service=step_data.get('service'),
            package=step_data.get('package'),
            user=step_data.get('user'),
            conditions=step_conditions,
        )
