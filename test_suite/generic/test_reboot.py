import pytest
from lib import test_lib


class TestsReboot:
    hostname_before_reboot_file = '/var/hostname_before_reboot'
    kmemleak_arg = 'kmemleak=on'

    def setup_before_reboot(self, host):
        with host.sudo():
            host.run(f'hostname > {self.hostname_before_reboot_file}')
            host.run_test(f'grubby --update-kernel=ALL --args="{self.kmemleak_arg}"')

    @pytest.mark.order(101)
    @pytest.mark.run_on(['all'])
    def test_launch_reboot(self, host, instance_data):
        self.setup_before_reboot(host)
        test_lib.reboot_host(host)

    @pytest.mark.order(102)
    @pytest.mark.run_on(['all'])
    def test_reboot_time(self, host, instance_data):
        """
        Check reboot time after 1st init.
        BugZilla 1776710, 1446698, 1446688
        """
        if instance_data['cloud'] == 'azure':
            max_boot_time_seconds = 60.0
        else:
            max_boot_time_seconds = 40.0

        boot_time = test_lib.get_host_last_boot_time(host)

        assert boot_time < max_boot_time_seconds, \
            f'Reboot took more than {max_boot_time_seconds} sec.'

    @pytest.mark.order(103)
    @pytest.mark.run_on(['all'])
    def test_reboot_keeps_current_hostname(self, host):
        """
        Check that reboot doesn't change the hostname
        """
        hostname_after_reboot = host.check_output('hostname')

        with host.sudo():
            assert host.file(self.hostname_before_reboot_file).contains(hostname_after_reboot), \
                'Instance hostname changed after reboot'

    # TODO: Review failure in RHEL 7.9, it may be related to a grubby bug
    @pytest.mark.order(104)
    @pytest.mark.run_on(['all'])
    def test_reboot_grubby(self, host):
        """
        Check that user can update boot parameter using grubby tool
        """
        file_to_check = '/proc/cmdline'

        with host.sudo():
            assert host.file(file_to_check).contains(self.kmemleak_arg), \
                f'Expected "{self.kmemleak_arg}" in "{file_to_check}"'

            host.run_test(f'grubby --update-kernel=ALL --remove-args="{self.kmemleak_arg}"')

    @pytest.mark.run_on(['all'])
    def test_first_boot_time(self, host, instance_data):
        if instance_data['cloud'] == 'azure':
            max_boot_time_aws = 120
        elif host.system_info.arch == 'aarch64':
            max_boot_time_aws = 70
        else:
            max_boot_time_aws = 60

        boot_time = test_lib.get_host_last_boot_time(host)

        assert boot_time < max_boot_time_aws, f'First boot took more than {max_boot_time_aws} seconds'
