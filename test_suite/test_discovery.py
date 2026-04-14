"""Test discovery and format detection utilities."""

import os
from pathlib import Path
from typing import List, Tuple, Optional


def discover_tests_in_path(path: str, format_filter: Optional[str] = None) -> List[str]:
    """
    Discover test files in a path.
    
    Args:
        path: File or directory path
        format_filter: 'yaml', 'pytest', or None for auto-detect
        
    Returns:
        List of test file paths
    """
    results = []
    path_obj = Path(path)
    
    if path_obj.is_file():
        # Single file
        if _matches_format(path, format_filter):
            results.append(path)
    elif path_obj.is_dir():
        # Directory - search recursively
        if format_filter in [None, 'yaml']:
            results.extend(path_obj.rglob('*.yaml'))
        if format_filter in [None, 'pytest', 'py']:
            results.extend(path_obj.rglob('test_*.py'))
        results = [str(p) for p in results]
    
    return results


def split_by_format(test_paths: List[str]) -> Tuple[List[str], List[str]]:
    """
    Split test paths by format.
    
    Args:
        test_paths: List of test file paths
        
    Returns:
        (yaml_tests, pytest_tests)
    """
    yaml_tests = []
    pytest_tests = []
    
    for path in test_paths:
        if path.endswith('.yaml') or path.endswith('.yml'):
            yaml_tests.append(path)
        elif path.endswith('.py'):
            pytest_tests.append(path)
    
    return yaml_tests, pytest_tests


def is_yaml_test(path: str) -> bool:
    """Check if path is a YAML test file."""
    return path.endswith('.yaml') or path.endswith('.yml')


def is_pytest_test(path: str) -> bool:
    """Check if path is a pytest test file."""
    return path.endswith('.py') and 'test_' in path


def _matches_format(path: str, format_filter: Optional[str]) -> bool:
    """Check if a path matches the format filter."""
    if format_filter is None:
        return True
    elif format_filter in ['yaml', 'yml']:
        return path.endswith(('.yaml', '.yml'))
    elif format_filter in ['pytest', 'py']:
        return path.endswith('.py') and 'test_' in path
    return False


def get_test_format(path: str) -> str:
    """
    Determine the format of a test file.
    
    Returns:
        'yaml', 'pytest', or 'unknown'
    """
    if is_yaml_test(path):
        return 'yaml'
    elif is_pytest_test(path):
        return 'pytest'
    else:
        return 'unknown'
