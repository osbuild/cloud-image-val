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
