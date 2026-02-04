import pytest
from packaging import version
from lib import test_lib, console_lib
from test_suite.generic.test_generic import TestsSubscriptionManager as sub_man
from test_suite.rhel_devel import run_cloudx_components_testing

"""
CUT (Components Upgrade Testing) refers to the RHEL testing phase
were we test if our components are upgradable across major versions.
Example: After upgrading from RHEL-9.6 to RHEL-10.0, make sure components work.
"""


@pytest.mark.cut
class TestsComponentsUpgrade:
    @pytest.mark.run_on(['rhel9.8', 'rhel10.2'])
    def test_cut_rhel_90_to_rhel_100(self, host, instance_data):
        console_lib.print_divider('Testing components BEFORE major upgrade...')
        assert run_cloudx_components_testing.main()

        console_lib.print_divider('Registering system with subscription-manager...')
        sub_man_config = {
            "rhsmcertd.auto_registration": 1,
            "rhsm.manage_repos": 1,
        }
        for item, value in sub_man_config.items():
            with host.sudo():
                host.run_test(f'subscription-manager config --{item}={value}')

        sub_man.test_subscription_manager_auto(self, host, instance_data)

        console_lib.print_divider('Migrating legacy network configuration workaround')
        if host.file('/etc/sysconfig/network-scripts/ifcfg-eth0').exists:
            test_lib.print_host_command_output(
                host,
                'nmcli connection migrate /etc/sysconfig/network-scripts/ifcfg-eth0'
            )

        console_lib.print_divider('Installing leapp package...')
        result = test_lib.print_host_command_output(host, 'dnf install leapp-upgrade-el9toel10 -y', capture_result=True)

        assert result.succeeded, 'Failed to install leapp-upgrade-el9toel10'

        # We will use the latest compose by defualt.
        # This can be manually changed in a CIV pull request for debugging purposes.
        compose_url = "http://download.devel.redhat.com/rhel-10/nightly/RHEL-10/latest-RHEL-10.2"

        basearch = host.system_info.arch

        console_lib.print_divider('Adding RHEL-10 repos...')
        repo_file_name = '/etc/yum.repos.d/rhel10.repo'
        rhel_10_repo_file = f"""
[AppStream10]
name=AppStream for RHEL-10
baseurl={compose_url}/compose/AppStream/{basearch}/os/
enabled=0
gpgcheck=0

[BaseOS10]
name=BaseOS for RHEL-10
baseurl={compose_url}/compose/BaseOS/{basearch}/os/
enabled=0
gpgcheck=0
"""
        test_lib.print_host_command_output(host, f'echo "{rhel_10_repo_file}" > {repo_file_name}')

        console_lib.print_divider('Running leapp upgrade...')
        result = test_lib.print_host_command_output(
            host,
            'LEAPP_UNSUPPORTED=1 LEAPP_DEVEL_SKIP_CHECK_OS_RELEASE=1 '
            'leapp upgrade --no-rhsm --enablerepo AppStream10 --enablerepo BaseOS10',
            capture_result=True)

        if result.failed:
            reapp_report_file = '/var/log/leapp/leapp-report.txt'
            if host.file(reapp_report_file).exists:
                print('Leapp Report:\n', host.file(reapp_report_file).content_string)

            pytest.fail('RHEL major upgrade failed. Please check leapp-report.txt for more details.')

        console_lib.print_divider('Rebooting host...')
        # 15 minutes of timeout due to performing a major upgrade
        host = test_lib.reboot_host(host, max_timeout=900)

        assert version.parse(host.system_info.release).major == 10, \
            'Failed to upgrade from RHEL-9.8 to RHEL-10.2 even after reboot.'

        console_lib.print_divider('Testing components AFTER major upgrade...')
        assert run_cloudx_components_testing.main()
