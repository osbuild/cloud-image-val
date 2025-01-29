import pytest
from packaging import version
from lib import test_lib, console_lib
from test_suite.generic.test_generic import TestsSubscriptionManager as sub_man
from test_suite.rhel_devel.test_cloudx_components import test_cloudx_components

"""
CUT (Components Upgrade Testing) refers to the RHEL testing phase
were we test our components are upgradable across major versions.
Example: After upgrading from RHEL-9.6 to RHEL-10.0, make sure my components pass testing.
"""


@pytest.mark.cut
@pytest.mark.run_on(['rhel9.6', 'rhel10.0'])
class TestsRhel96to100:
    def test_components_upgrade(self, host, instance_data):
        console_lib.print_divider('Testing components before major upgrade...')
        test_cloudx_components(host)

        console_lib.print_divider('Registering system with subscription-manager...')
        sub_man.test_subscription_manager_auto(self, host, instance_data)

        console_lib.print_divider('Installing leapp package...')
        result = test_lib.print_host_command_output(host, 'dnf install leapp-upgrade-el9toel10 -y', capture_result=True)

        assert result.succeeded, 'Failed to install leapp-upgrade-el9toel10'

        console_lib.print_divider('Adding RHEL-10 repos...')
        repo_file_name = '/etc/yum.repos.d/rhel10.repo'
        rhel_10_repo_file = """
[AppStream10]
name=AppStream for RHEL-10
baseurl=$COMPOSE_URL/compose/AppStream/$basearch/os/
enabled=0
gpgcheck=0

[BaseOS10]
name=BaseOS for RHEL-10
baseurl=$COMPOSE_URL/compose/BaseOS/$basearch/os/
enabled=0
gpgcheck=0
"""
        test_lib.print_host_command_output(host, f'echo "{rhel_10_repo_file}" > {repo_file_name}')

        console_lib.print_divider('Running leapp upgrade...')
        result = test_lib.print_host_command_output(
            host,
            'leapp upgrade --no-rhsm --enablerepo AppStream10 --enablerepo BaseOS10',
            capture_result=True)

        console_lib.print_divider('Running leapp upgrade...')
        if result.failed:
            reapp_report_file = '/var/log/leapp/leapp-report.txt'
            if host.file(reapp_report_file).exists:
                print('Leapp Report:\n', host.file(reapp_report_file).content_string)

            pytest.fail('RHEL major upgrade failed. Please check leapp-report.txt for more details.')

        console_lib.print_divider('Rebooting host...')
        host = test_lib.reboot_host(host)

        assert version.parse(host.system_info.release).major == 10, \
            'Failed to upgrade from RHEL-9.6 to RHEL-10.0 even after reboot.'

        test_cloudx_components(host)
