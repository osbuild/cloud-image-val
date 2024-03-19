import pytest

from lib import test_lib


@pytest.mark.package
@pytest.mark.run_on(['rhel9.4'])
class TestsEfsUtils:
    def test_efs_utils(self, host, instance_data):
        """
        NOTE: This test case assumes efs-utils is preinstalled in the AMI image
        Check basic functionality of EFS utils:
        - Create a mount point and mount the EFS file system to the RHEL instance.
        - Create a file on the mount point.
        - Automate mount on boot.
        - Checksum the file before reboot.
        - reboot and checksum that the file is correct.
        """
        # will get 'file_system_dns_name' arg form the fixture that gets the output of the Terraform script
        file_system_dns_name = instance_data['efs_file_system_dns_name']
        test_file = '/mnt/efs/testfile'
        with host.sudo():
            assert host.run_test(
                f'mkdir /mnt/efs && mount -t efs {file_system_dns_name} /mnt/efs/'
            ), f'Failed mount {file_system_dns_name} to efs folder'

            assert host.mount_point('/mnt/efs').exists

            assert host.run_test(
                f'dd if=/dev/zero of={test_file} bs=3K count=1'), 'Failed to write the file'

            assert host.run_test(f'echo "{file_system_dns_name}:/ /mnt/efs efs _netdev,tls 0 0" >> "/etc/fstab"'), \
                'Failed to write fstab'

            checksum_before_reboot = host.file(test_file).md5sum
            test_lib.reboot_host(host)
            assert checksum_before_reboot == host.file(test_file).md5sum
