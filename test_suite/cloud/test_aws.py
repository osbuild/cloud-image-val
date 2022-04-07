class TestsAWS:
    def test_rh_cloud_firstboot_service_is_disabled(self, host):
        assert not host.service('rh-cloud-firstboot').is_enabled,\
            'rh-cloud-firstboot service must be disabled'

        cloud_firstboot_file = host.file('/etc/sysconfig/rh-cloud-firstboot')
        # TODO: Confirm if test should fail when this file does not exist
        if cloud_firstboot_file.exists:
            assert cloud_firstboot_file.contains('RUN_FIRSTBOOT=NO'), \
                'rh-cloud-firstboot must be configured with RUN_FIRSTBOOT=NO'

    def test_cmdline_console_is_redirected_to_ttys0(self, host):
        assert host.file('/proc/cmdline').contains('console=ttyS0'),\
            'Serial console should be redirected to ttyS0'
