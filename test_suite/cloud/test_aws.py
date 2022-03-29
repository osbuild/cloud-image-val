import re
import pytest


class TestsAWS:
    def test_stage1_check_cloud_firstboot_config(self, host):
        pytest.skip("Broken test. Command doesn't work and file doesn't exist.")
        with host.sudo():
            std_out = host.check_output('chkconfig --list rh-cloud-firstboot')
            assert re.match('3:off', std_out), 'rh-cloud-firstboot must be disabled'

            assert host.file('/etc/sysconfig/rh-cloud-firstboot').contains('RUN_FIRSTBOOT=NO'), \
                'rh-cloud-firstboot must be configured'

    def test_stage1_check_cmdline_console(self, host):
        assert host.file('/proc/cmdline').contains('console=ttyS0'), 'Serial console should be redirected to ttyS0'
