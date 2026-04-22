"""
Test decorators for marking test conditions.

These decorators wrap pytest.mark to provide a stable interface for
specifying when tests should run on which distributions/versions.
"""

import pytest


def run_on(distros):
    """
    Mark test to run on specific distributions or versions.

    Args:
        distros: List of distributions/versions to run on.
                 Can include: 'all', 'rhel', 'fedora', 'rhel9', 'rhel>=9', etc.

    Examples:
        @run_on(['all'])
        def test_basic_feature(host):
            pass

        @run_on(['rhel>=9', 'fedora'])
        def test_modern_feature(host):
            pass

        @run_on(['rhel9', 'rhel10'])
        def test_specific_versions(host):
            pass
    """
    return pytest.mark.run_on(distros)


def exclude_on(distros):
    """
    Mark test to be excluded on specific distributions or versions.

    Args:
        distros: List of distributions/versions to exclude.
                 Can include: 'rhel', 'fedora', 'rhel8', 'rhel<9', etc.

    Examples:
        @run_on(['all'])
        @exclude_on(['rhel8'])
        def test_not_on_rhel8(host):
            pass

        @run_on(['rhel'])
        @exclude_on(['rhel<9'])
        def test_rhel9_and_above(host):
            pass
    """
    return pytest.mark.exclude_on(distros)


def wait(seconds):
    """
    Mark test to wait specified seconds before running.

    Useful for tests that need time for services to stabilize, etc.

    Args:
        seconds: Number of seconds to wait before running test

    Example:
        @run_on(['all'])
        @wait(30)
        def test_after_boot_settle(host):
            # Wait 30 seconds for services to stabilize
            pass
    """
    return pytest.mark.wait(seconds)
