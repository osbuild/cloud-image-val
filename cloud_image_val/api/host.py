"""
Host information utilities for extracting and working with host metadata.

Provides a stable interface for getting host information (distro, version, arch)
from testinfra host objects.
"""

from dataclasses import dataclass
from packaging import version


@dataclass
class HostInfo:
    """Structured host metadata."""
    distro: str
    version: str
    arch: str
    hostname: str

    @property
    def distro_version(self) -> str:
        """Get combined distro and major version (e.g., 'rhel9')."""
        major_version = version.parse(self.version).major
        return f"{self.distro}{major_version}"

    @property
    def version_parsed(self):
        """Get parsed version for comparisons."""
        return version.parse(self.version)


def get_host_info(host) -> HostInfo:
    """
    Extract host information from a testinfra host object.

    Args:
        host: testinfra host fixture object

    Returns:
        HostInfo object with distro, version, arch, hostname

    Example:
        def test_something(host):
            info = get_host_info(host)
            if info.distro == 'rhel' and info.version_parsed >= version.parse('9.0'):
                # RHEL 9+ specific test logic
                pass
    """
    return HostInfo(
        distro=host.system_info.distribution,
        version=host.system_info.release,
        arch=host.system_info.arch,
        hostname=host.backend.hostname
    )
