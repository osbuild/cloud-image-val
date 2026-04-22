"""
Cloud Image Validator - Stable Test Library API

This package provides a stable API for writing cloud image validation tests.
External test repositories can depend on this package and use its helpers
while cloud-image-val's internals can evolve independently.

Version: 1.0.0
"""

__version__ = "1.0.0"

# Re-export stable public API
from cloud_image_val.api.decorators import run_on, exclude_on, wait
from cloud_image_val.api.assertions import (
    assert_file_exists,
    assert_file_not_exists,
    assert_file_empty,
    assert_file_contains,
    assert_command_succeeds,
    assert_command_fails,
    assert_no_avc_denials,
    assert_package_installed,
    assert_package_not_installed,
    assert_service_running,
    assert_service_enabled,
)
from cloud_image_val.api.host import HostInfo, get_host_info

__all__ = [
    # Version
    "__version__",
    # Decorators
    "run_on",
    "exclude_on",
    "wait",
    # Assertions
    "assert_file_exists",
    "assert_file_not_exists",
    "assert_file_empty",
    "assert_file_contains",
    "assert_command_succeeds",
    "assert_command_fails",
    "assert_no_avc_denials",
    "assert_package_installed",
    "assert_package_not_installed",
    "assert_service_running",
    "assert_service_enabled",
    # Host utilities
    "HostInfo",
    "get_host_info",
]
