import pytest


class TestsAWS:
    def test_rh_cloud_firstboot_service_is_disabled(self, host):
        assert not host.service('rh-cloud-firstboot').is_enabled, \
            'rh-cloud-firstboot service must be disabled'

        with host.sudo():
            cloud_firstboot_file = host.file('/etc/sysconfig/rh-cloud-firstboot')
            # TODO: Confirm if test should fail when this file does not exist
            if cloud_firstboot_file.exists:
                assert cloud_firstboot_file.contains('RUN_FIRSTBOOT=NO'), \
                    'rh-cloud-firstboot must be configured with RUN_FIRSTBOOT=NO'

    def test_iommu_strict_mode(self, host):
        """
        BugZilla 1836058
        """
        option = 'iommu.strict=0'

        with host.sudo():
            product_version = 8.5
            if float(host.system_info.release) < product_version and \
                    not host.file('/etc/redhat-release').contains('Atomic'):
                pytest.skip(f'Not applicable to RHEL AMIs earlier than {product_version}')

                iommu_option_present = host.file('/proc/cmdline').contains(option)

                if host.system_info.arch == 'x86_64':
                    assert not iommu_option_present, f'{option} must not be present in x86_64 AMIs'
                else:
                    assert iommu_option_present, f'{option} must be present in ARM AMIs'

    def test_nouveau_is_blacklisted(self, host):
        """
        BugZilla 1645772
        """
        product_version = float(host.system_info.release)

        if product_version < 7.0:
            pytest.skip('Not required in RHEL 6.x')

        with host.sudo():
            assert host.file('/proc/cmdline').contains('rd.blacklist=nouveau'), \
                'nouveau must be blacklisted in cmdline'

        if product_version < 8.5:
            file_to_check = '/etc/modprobe.d/blacklist-nouveau.conf'
        else:
            file_to_check = '/usr/lib/modprobe.d/blacklist-nouveau.conf'

        assert host.file(file_to_check).contains('blacklist nouveau'), \
            f'nouveau is not blacklisted in "{file_to_check}"'


class TestsNetworkDrivers:
    def test_correct_network_driver_is_used(self, host):
        with host.sudo():
            if not host.package('lshw').is_installed:
                host.run_test('dnf install lshw -y')

            nic_name = host.check_output('lshw -C network')
            nic_driver = host.check_output('lshw -C network | grep "driver="')

            self.__test_nic_is_using_correct_driver(nic_name, nic_driver)

            if 'Xen' not in host.check_output('lscpu'):
                assert 'ena' in nic_driver, 'ENA driver must de used in KVM, arch64 and metal instances'

    def __test_nic_is_using_correct_driver(self, nic_name, nic_driver):
        name_filter, driver_filter = self.__get_nic_filters_for_drivers(nic_name)

        assert driver_filter in nic_driver, \
            f'{name_filter} network adapter must use {driver_filter} driver'

    def __get_nic_filters_for_drivers(self, nic_name):
        if 'ENA' in nic_name:
            nic_name_filter = 'ENA'
            nic_driver_name_filter = 'ena'
        elif 'Virtual Function' in nic_name:
            nic_name_filter = 'Virtual Function'
            nic_driver_name_filter = 'ixgbevf'
        else:
            nic_name_filter = 'Other'
            nic_driver_name_filter = 'vif'

        return nic_name_filter, nic_driver_name_filter
