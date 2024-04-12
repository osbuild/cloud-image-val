import time

import pytest

from lib import test_lib, console_lib


@pytest.mark.package
@pytest.mark.run_on(['rhel9.4'])
class TestsEfsUtils:
    mount_point = '/tmp/efs'

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
        # We get 'file_system_dns_name' as instance metadata. See instance_data fixture in conftest.py
        file_system_dns_name = instance_data['efs_file_system_dns_name']

        # Adding current timestamp to prevent I/O issues
        test_file = f'{self.mount_point}/testfile_{time.time()}'

        result = host.run(f'mkdir {self.mount_point}')
        with host.sudo():
            assert result.succeeded, f'Could not create mount point directory. {result.stderr}'
            console_lib.print_divider(f'Mount point {self.mount_point} created.',
                                      upper=False, center_text=False)

            result = host.run(f'mount -t efs {file_system_dns_name} {self.mount_point}')
            assert result.succeeded, \
                f'Failed to mount {file_system_dns_name} into {self.mount_point}. {result.stderr}'
            assert host.mount_point(self.mount_point).exists
            console_lib.print_divider(f'EFS file system {file_system_dns_name} successfully mounted.',
                                      upper=False, center_text=False)

            result = host.run(f'dd if=/dev/zero of={test_file} bs=3K count=1')
            assert result.succeeded, f'Failed to write the test file. {result.stderr}'
            console_lib.print_divider(host.check_output(f'ls -l {test_file}'),
                                      upper=False, center_text=False)
            console_lib.print_divider(f'Test file {test_file} successfully written.',
                                      upper=False, center_text=False)

            write_fstab_cmd = f'echo "{file_system_dns_name}:/ {self.mount_point} efs _netdev,tls 0 0" >> "/etc/fstab"'

            result = host.run(write_fstab_cmd)
            assert result.succeeded, f'Failed to update /etc/fstab. {result.stderr}'
            console_lib.print_divider('/etc/fstab updated successfully.', upper=False, center_text=False)

            checksum_before_reboot = host.file(test_file).md5sum

            test_lib.reboot_host(host)

            assert checksum_before_reboot == host.file(test_file).md5sum
            console_lib.print_divider(f'{test_file} checksum is the expected one!', center_text=False)
