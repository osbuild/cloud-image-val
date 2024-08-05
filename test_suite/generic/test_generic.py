import os
import re
import time

import pytest
from packaging import version

from lib import console_lib
from lib import test_lib


@pytest.fixture(scope='class')
def check_kdump_fix_condition(host):
    arch = host.system_info.arch

    if arch == 'aarch64':
        get_ram_size = host.check_output("free -h | awk '/^Mem:/ {print $2}'")
        ram_size = (float(get_ram_size[:-2]))
        kernel_version = host.check_output('uname -r').split("-")[0]

        # BugZilla 2214235
        if version.parse(kernel_version) < version.parse('4.18.0'):
            pytest.skip(f'Skip on arm64 with kernel version {kernel_version}')

        if version.parse(kernel_version) > version.parse('4.18.0') and ram_size <= 4.0:
            pytest.skip('Skip on arm64 if kernel version higher than 4.18.0 '
                        'while ram size is smaller than 4Gib')


@pytest.mark.order(1)
class TestsGeneric:
    @pytest.mark.run_on(['all'])
    def test_no_avc_denials(self, host, instance_data):
        """
        Check there is no avc denials (selinux).
        """
        if (host.system_info.distribution == 'rhel' and float(host.system_info.release) == 9.4) \
           or (host.system_info.distribution == 'centos' and host.system_info.release == "9"):
            pytest.skip('RHEL-24346: Skipping on RHEL-9.4 due to a known issue with NetworkManager.')

        # CLOUDX-320: This "if" is pending to be removed
        if instance_data['cloud'] == 'azure':
            pytest.skip('Skipping on fedora due to old image definitions')

        command_to_run = 'x=$(ausearch -m avc 2>&1 &); echo $x'
        result = test_lib.print_host_command_output(host,
                                                    command_to_run,
                                                    capture_result=True)

        no_avc_denials_found = 'no matches' in result.stdout

        assert no_avc_denials_found, 'There should not be any avc denials (selinux)'

    @pytest.mark.run_on(['all'])
    def test_bash_history_is_empty(self, host):
        users = [host.user().name, 'root']

        for u in users:
            file_path = f'/home/{u}/.bash_history'
            bash_history_file = host.file(file_path)
            if bash_history_file.exists:
                file_content_length = len(bash_history_file.content_string)
                assert file_content_length == 0, f'{file_path} must be empty or nonexistent'

    # TODO: Confirm if this test should be run in non-RHEL images
    @pytest.mark.run_on(['rhel'])
    def test_username(self, host, instance_data):
        for user in ['fedora', 'cloud-user']:
            with host.sudo():
                assert not host.user(user).exists, 'Unexpected username in instance'

            assert host.check_output('whoami') == instance_data['username']

    @pytest.mark.run_on(['all'])
    def test_console_is_redirected_to_ttys0(self, host):
        """
        Console output should be redirected to serial for HVM instances.
        """
        assert host.file('/proc/cmdline').contains('console=ttyS0'), \
            'Serial console should be redirected to ttyS0'

    # TODO: does this apply to fedora and centos
    @pytest.mark.run_on(['rhel'])
    def test_crashkernel_is_enabled_rhel(self, host):
        """
        Check that crashkernel is enabled in image.
        """
        system_release = version.parse(host.system_info.release)

        if system_release < version.parse('9.0'):
            expected_content = 'crashkernel=auto'
        else:
            with host.sudo():
                expected_content = str(host.check_output('kdumpctl showmem 2>&1 | grep -oP "[0-9]*"'))

        with host.sudo():
            print(console_lib.print_debug({"expected_content": expected_content,
                                           "/proc/cmdline content": host.file("/proc/cmdline").content_string,
                                           "kdumpctl showmem": host.check_output("kdumpctl showmem 2>&1"),
                                           "kexec-tools version": host.package("kexec-tools").version}))

            assert host.file('/proc/cmdline').contains(expected_content), \
                'crashkernel must be enabled'

    @pytest.mark.run_on(['all'])
    def test_cpu_flags_are_correct(self, host, instance_data):
        """
        Check various CPU flags for x86_64 instances.
        BugZilla 1061348
        """
        current_arch = host.system_info.arch

        if current_arch != 'x86_64':
            pytest.skip(f'Not applicable to {current_arch}')

        expected_flags = [
            'avx',
            'xsave',
        ]

        if instance_data['cloud'] == 'azure':
            expected_flags.append('pcid')

        with host.sudo():
            for flag in expected_flags:
                assert host.file('/proc/cpuinfo').contains(flag), \
                    f'Expected CPU flag "{flag}" not set'

    @pytest.mark.run_on(['all'])
    def test_rhgb_quiet_not_present_in_cmdline(self, host):
        """
        Check that there is no "rhgb" or "quiet" in /proc/cmdline.
        BugZilla 1122300
        """
        excluded_settings = [
            'rhgb',
            'quiet',
        ]

        with host.sudo():
            for setting in excluded_settings:
                assert not host.file('/proc/cmdline').contains(setting), \
                    f'{setting} must not be present in cmdline'

    @pytest.mark.run_on(['all'])
    def test_numa_settings(self, host):
        """
        Check if NUMA is enabled on supported image.
        """
        with host.sudo():
            assert host.run_test('dmesg | grep -i numa'), \
                'There is no NUMA information available'

            lscpu_numa_nodes = host.check_output("lscpu | grep -i 'NUMA node(s)' | awk -F' ' '{print $NF}'")
            dmesg_numa_nodes = host.check_output("dmesg | grep -i 'No NUMA'|wc -l")

            if int(lscpu_numa_nodes) > 1:
                assert dmesg_numa_nodes > 1, \
                    f'NUMA seems to be disabled, when it should be enabled (NUMA nodes: {lscpu_numa_nodes})'

    @pytest.mark.run_on(['rhel'])
    def test_cert_product_version_is_correct(self, host):
        """
        BugZilla 1938930
        Issue RHELPLAN-60817
        """
        system_release = version.parse(host.system_info.release)

        if system_release < version.parse('8.0'):
            rpm_to_check = 'redhat-release-server'
        else:
            rpm_to_check = 'redhat-release'

        with host.sudo():
            host.run_test(f'rpm -q {rpm_to_check}')

            cert_version = host.check_output('rct cat-cert /etc/pki/product-default/*.pem | grep Version')

            assert f'Version: {system_release}' in cert_version, \
                'Inconsistent version in pki certificate'

    @pytest.mark.run_on(['all'])
    def test_inittab_and_systemd(self, host):
        """
        Check default runlevel or systemd target.
        """
        kernel_release = host.check_output('uname -r')

        print(f'Kernel release: {kernel_release}')

        with host.sudo():
            if host.package('systemd').is_installed:
                assert '/lib/systemd/system/multi-user.target' in \
                       host.check_output('readlink -f /etc/systemd/system/default.target'), \
                    'Unexpected systemd default target'
            else:
                assert 'id:3:initdefault' in host.check_output("grep '^id:' /etc/inittab"), \
                    'Unexpected default inittab "id"'

                if 'el5' in kernel_release:
                    assert 'si::sysinit:/etc/rc.d/rc.sysinit' in host.check_output("grep '^si:' /etc/inittab"), \
                        'Unexpected default inittab "id"'

    # TODO: does this apply to centos
    # TODO: fix docstring
    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_release_version(self, host):
        """
        Check if rhel provider matches /etc/redhat-release
        """
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not run in atomic images')

        system_release = version.parse(host.system_info.release)

        release_file = 'redhat-release'
        if host.system_info.distribution == 'fedora':
            release_file = 'fedora-release'

        with host.sudo():
            command_to_run = "rpm -q --qf '%{VERSION}' --whatprovides " + release_file
            package_release = version.parse(host.check_output(command_to_run))

        assert system_release == package_release, \
            f'Product version ({system_release}) does not match package release version'

    @pytest.mark.run_on(['rhel'])
    def test_root_is_locked(self, host):
        """
        Check if root account is locked
        """
        with host.sudo():
            if test_lib.is_rhel_atomic_host(host):
                result = host.run('passwd -S root | grep -q Alternate').rc
            else:
                result = host.run('passwd -S root | grep -q LK').rc
        assert result == 0, 'Root account should be locked'

    @pytest.mark.run_on(['all'])
    def test_bash_in_shell_config(self, host):
        """
        Check for bash/nologin shells in /etc/shells
        """
        assert host.file('/etc/shells').contains('/bin/bash'), \
            '/bin/bash is not declared in /etc/shells'

    # TODO: create test case for aarch64 grub config file
    @pytest.mark.run_on(['rhel'])
    def test_grub_config(self, host):
        current_arch = host.system_info.arch
        if current_arch != 'x86_64':
            pytest.skip(f'Not applicable to {current_arch}')

        grub2_file = '/boot/grub2/grubenv'
        linked_to = grub2_file

        with host.sudo():
            if host.file('/sys/firmware/efi').exists:
                if version.parse(host.system_info.release) < version.parse('8.0'):
                    linked_to = '/boot/efi/EFI/redhat/grubenv'

            assert host.file(grub2_file).linked_to == linked_to

    @pytest.mark.run_on(['rhel'])
    def test_tty0_config(self, host):
        """
        BugZilla 1103344
        Check that "/etc/init/ttyS0.conf" and its backup file do not exist.
        """
        with host.sudo():
            assert not host.file('/etc/init/ttyS0.conf').exists, 'ttyS0.conf file should not exist'
            assert not host.file('/etc/init/ttyS0.bak').exists, 'ttyS0.conf backup file should not exist'

    @pytest.mark.run_on(['rhel'])
    def test_selinux_mode(self, host):
        """
        BugZilla 1960628
        SELinux should be in enforcing/targeted mode
        """
        if test_lib.is_rhel_sap(host):
            expected_mode = 'Permissive'
        else:
            expected_mode = 'Enforcing'

        expected_file_config = [
            f'SELINUX={expected_mode.lower()}',
            'SELINUXTYPE=targeted'
        ]

        selinux_config_file = '/etc/sysconfig/selinux'

        with host.sudo():
            assert host.check_output('getenforce') == expected_mode, \
                f'SELinux should be in {expected_mode} mode'

            for conf in expected_file_config:
                assert host.file(selinux_config_file).contains(conf), \
                    f'Expected "{conf}" to be in {selinux_config_file}'

    @pytest.mark.run_on(['all'])
    def test_rpm_v_unsatisfied_dependencies(self, host):
        """
        Check unsatisfied dependencies of pkgs.
        """

        with host.sudo():
            assert 'Unsatisfied' not in host.run('rpm -Va').stdout, \
                'There are unsatisfied dependencies'

    @pytest.mark.run_on(['all'])
    def test_no_sshkeys_knownhosts(self, host):
        """
        Verify no extra files under /root/.ssh/ except authorized_keys
        """
        with host.sudo():
            ssh_files = host.file('/root/.ssh/').listdir()
            assert 'authorized_keys' in ssh_files, 'authorized_keys is not in /root/.ssh/'
            assert len(ssh_files) == 1, 'there are extra files in /root/.ssh/'

    @pytest.mark.run_on(['all'])
    def test_no_extra_public_keys(self, host):
        """
        Verify there's only one key in /root/.ssh/authorized_keys
        BugZilla 2127969
        """
        with host.sudo():
            debug = host.file('/root/.ssh/authorized_keys').content_string
            print(debug)

            authorized_keys_lines = host.check_output('cat /root/.ssh/authorized_keys | wc -l')
            assert authorized_keys_lines == '1', 'There is more than one public key in authorized_keys'

    @pytest.mark.run_on(['rhel'])
    @pytest.mark.exclude_on(['rhel7.9'])
    def test_dnf_conf(self, host, instance_data):
        """
        Check /etc/dnf/dnf.conf
        """
        local_file = 'data/generic/dnf.conf'
        file_to_check = '/etc/dnf/dnf.conf'

        if instance_data['cloud'] == 'gcloud':
            local_file = 'data/google/dnf.conf'

        assert test_lib.compare_local_and_remote_file(host, local_file, file_to_check), \
            f'{file_to_check} has unexpected content'

    @pytest.mark.run_on(['rhel'])
    def test_langpacks_conf(self, host):
        """
        Verify /etc/yum/pluginconf.d/langpacks.conf
        """
        local_file = 'data/generic/langpacks.conf'
        file_to_check = '/etc/yum/pluginconf.d/langpacks.conf'

        with host.sudo():
            if version.parse(host.system_info.release) < version.parse('8.0'):
                assert test_lib.compare_local_and_remote_file(host, local_file, file_to_check), \
                    f'{file_to_check} has unexpected content'
            else:
                assert not host.file(file_to_check).exists, \
                    f'{file_to_check} should not exist in RHEL-8 and above'


@pytest.mark.order(3)
class TestsServices:
    @pytest.mark.run_on(['all'])
    def test_sshd(self, host):
        """
        Verify that SSH password authentication is disabled.

        By default, the configuration is in /etc/ssh/sshd_config
        Starting from Fedora 38, the configuration is in /etc/ssh/sshd_config.d/50-cloud-init.conf
        Starting from RHEL 9.3 and 8.9, the configuration is in /etc/ssh/sshd_config.d/50-redhat.conf

        JIRA: CLOUDX-484, COMPOSER-1959
        """

        # cloud-init >= 22.3 puts extra sshd configs into a separate file
        # see https://github.com/canonical/cloud-init/pull/1618
        possible_sshd_auth_config_settings = [
            {
                'path': '/etc/ssh/sshd_config',
                'config_key': 'PasswordAuthentication',
                'config_value': 'no'
            },
            {
                'path': '/etc/ssh/sshd_config.d/50-cloud-init.conf',
                'config_key': 'PasswordAuthentication',
                'config_value': 'no'
            },
            {
                'path': '/etc/ssh/sshd_config.d/50-redhat.conf',
                'config_key': 'ChallengeResponseAuthentication',
                'config_value': 'no'
            },
        ]

        with host.sudo():
            print(f' - openssh-server version: {host.run("rpm -qa | grep openssh-server").stdout}')

            sshd = host.service('sshd')
            if not sshd.is_running:
                print(f' - journalctl -u sshd.service: {host.check_output("journalctl -u sshd.service")}')
                pytest.fail('ssh.service is not running')

            is_sshd_auth_forced_to_disabled = False
            for possible_config in possible_sshd_auth_config_settings:
                file_path = possible_config['path']
                config_key = possible_config['config_key']
                config_value = possible_config['config_value']

                if host.file(file_path).exists and host.file(file_path).contains(f'^{config_key} {config_value}'):
                    print(host.run(f'ls -l {file_path}').stdout)

                    print('SSH password authentication config found:')
                    print(f'\tFile path:\t{file_path}')
                    print(f'\tConfig key:\t{config_key}')
                    print(f'\tConfig value:\t{config_value}')

                    print('-' * 50)

                    is_sshd_auth_forced_to_disabled = True

        assert is_sshd_auth_forced_to_disabled, 'Password authentication via ssh must be disabled.'

    @pytest.mark.run_on(['rhel', 'centos'])
    def test_sysconfig_kernel(self, host):
        """
        UPDATEDEFAULT=yes and DEFAULTKERNEL=kernel should be set in /etc/sysconfig/kernel
        """
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not run in atomic images')

        kernel_config = '/etc/sysconfig/kernel'
        with host.sudo():
            assert host.file(kernel_config).contains('UPDATEDEFAULT=yes'), \
                f'UPDATEDEFAULT should be set to `yes` in {kernel_config}'
            assert host.file(kernel_config).contains('DEFAULTKERNEL=kernel'), \
                f'DEFAULTKERNEL should be set to `kernel` in {kernel_config}'

    @pytest.mark.run_on(['all'])
    @pytest.mark.usefixtures('check_kdump_fix_condition')
    def test_no_fail_service(self, host):
        """
        Verify no failed service
        """
        with host.sudo():
            result = host.run('systemctl list-units | grep -i fail')

            print(result.stdout)

            failing_services = []

            failing_service_regex = r'^● (?P<service>.*).service\s+'

            failing_services_lines = result.stdout.split('\n')
            for line in failing_services_lines:
                regex_match = re.match(failing_service_regex, line)

                if regex_match:
                    failing_service_data = regex_match.groupdict()

                    service_name = failing_service_data['service']
                    failing_services.append(service_name)

                    test_lib.print_host_command_output(host, f'systemctl status {service_name}')

                    test_lib.print_host_command_output(
                        host,
                        f'rpm -qf "$(systemctl show --value --property=FragmentPath {service_name})"'
                    )
            failed_services_after_restart = []
            if len(failing_services) > 0:
                for service in failing_services:
                    print(f"{service} is failing, attempting restart...")

                    host.run(f"systemctl restart {service}")
                    time.sleep(5)

                    result = host.run(f"systemctl is-failed {service}")
                    if 'fail' in result.stdout:
                        print(f"Service {service} is still failing after restart")
                        failed_services_after_restart.append(service)

            assert len(failed_services_after_restart) == 0, \
                f'There are failing services: {",".join(failed_services_after_restart)}'


@pytest.mark.pub
@pytest.mark.run_on(['rhel'])
@pytest.mark.exclude_on(['<rhel8.3'])
class TestsSubscriptionManager:
    def test_subscription_manager_auto(self, host, instance_data):
        """
        BugZilla 8.4: 1932802, 1905398
        BugZilla 7.9: 2077086, 2077085
        """

        expected_config = [
            'auto_registration = 1',
            'manage_repos = 0'
        ]

        if instance_data['cloud'] == 'aws':
            region = instance_data['availability_zone'][:-1]

            # Refer to "Supported AWS AutoReg Regions" Google Spreadsheet (RHUI Team)
            # https://docs.google.com/spreadsheets/d/15bcP0a9fBaxHVbk6tXiBL8Hn5fLjkHx9GjNf06ctISI/
            unsupported_aws_regions = [
                'ap-south-2',
                'ap-southeast-4',
                'eu-south-2',
                'eu-central-2',
                'us-gov-east-1',
                'us-gov-west-1',
                'cn-northwest-1',
                'cn-north-1'
            ]

            if region in unsupported_aws_regions:
                pytest.skip(f'The {region} AWS region is not supported for auto-registration yet.')

        with host.sudo():
            for config in expected_config:
                assert config in host.check_output('subscription-manager config'), \
                    f'Expected "{config}" not found in subscription manager configuration'

            assert host.service(
                'rhsmcertd').is_enabled, 'rhsmcertd service must be enabled'

            assert host.run_test('subscription-manager config --rhsmcertd.auto_registration_interval=1'), \
                'Error while changing auto_registration_interval from 60min to 1min'

            assert host.run_test(
                'systemctl restart rhsmcertd'), 'Error while restarting rhsmcertd service'

            start_time = time.time()
            timeout = 360
            interval = 30

            while True:
                assert host.file('/var/log/rhsm/rhsmcertd.log').exists
                assert host.file('/var/log/rhsm/rhsm.log').exists
                assert host.run_test('subscription-manager identity')
                assert host.run_test('subscription-manager list --installed')

                subscription_status = host.run(
                    'subscription-manager status').stdout

                if 'Red Hat Enterprise Linux' in subscription_status or \
                        'Simple Content Access' in subscription_status:
                    print('Subscription auto-registration completed successfully')

                    if not host.run_test('insights-client --register'):
                        pytest.fail('insights-client command did not succeed after auto-registration completed')

                    break

                end_time = time.time()
                if end_time - start_time > timeout:
                    assert host.run_test('insights-client --register'), \
                        'insights-client could not register successfully'
                    pytest.fail(
                        f'Timeout ({timeout}s) while waiting for subscription auto-registration')

                print(f'Waiting {interval}s for auto-registration to succeed...')
                time.sleep(interval)

    def test_subscription_manager_auto_config(self, host):
        """
        BugZilla: 1932802, 1905398
        Verify that auto_registration is enabled in the image
        """
        expected_config = [
            'auto_registration = 1',
            'manage_repos = 0'
        ]

        file_to_check = '/etc/rhsm/rhsm.conf'

        with host.sudo():
            for item in expected_config:
                assert host.file(file_to_check).contains(item), \
                    f'{file_to_check} has unexpected content'

            assert host.service('rhsmcertd').is_enabled, \
                'rhsmcertd service is expected to be enabled'


@pytest.mark.order(1)
class TestsCloudInit:
    @pytest.mark.run_on(['all'])
    def test_growpart_is_present_in_config(self, host, instance_data):
        """
        Make sure there is "growpart" in cloud_init_modules group in "/etc/cloud/cloud.cfg".
        For Azure instances, make sure there is also "mounts" in the config.
        BugZilla 966888
        """
        config_to_check = ['- growpart']
        if instance_data['cloud'] == 'azure':
            config_to_check.append('- mounts')

        for config in config_to_check:
            assert host.file('/etc/cloud/cloud.cfg').contains(config), \
                f'{config} must be present in cloud_init_modules'

    @pytest.mark.run_on(['rhel'])
    @pytest.mark.exclude_on(['<rhel8.2'])
    def test_wheel_group_not_set_to_default_user(self, host):
        """
        Make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg".
        BugZilla 1549638, 1785648
        Customer Case 01965459
        """
        assert not host.file('/etc/cloud/cloud.cfg').contains('wheel'), \
            'wheel should not be configured as default_user group'

    @pytest.mark.run_on(['rhel'])
    def test_cloud_configs(self, host):
        """
        Verify files /etc/cloud/cloud.cfg and
        /etc/cloud/cloud.cfg.d/* are not changed

        JIRA: CLOUDX-812
        """
        if float(host.system_info.release) <= 8.4 and test_lib.is_rhel_sap(host):
            # Test skipped since it's applicable to RHEL-SAP kickstart-generated images
            pytest.skip('This test is not applicable for RHEL-SAP 8.4 and older.')

        cloud_cfg = '/etc/cloud/cloud.cfg'
        verify_cmd = f'rpm -Vf {cloud_cfg} | grep -e "^S.5.*{cloud_cfg}"'

        with host.sudo():
            assert not host.run(verify_cmd).stdout, \
                f'There should not be changes in {cloud_cfg} or {cloud_cfg}.d/'

    @pytest.mark.run_on(['>=rhel9.0'])
    def test_cloud_cfg_netdev_rhel9(self, host):
        """
        Verify _netdev is in cloud.cfg
        """
        with host.sudo():
            assert host.file('/etc/cloud/cloud.cfg').contains('_netdev'), \
                '_netdev is expected in cloud.cfg for RHEL 9.x'


@pytest.mark.pub
@pytest.mark.order(3)
class TestsYum:
    # TODO: confirm if this test needs to be deprecated
    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_yum_repoinfo(self, host):
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not applicable to RHEL Atomic host')

        yum_command = 'yum repoinfo'

        with host.sudo():
            assert host.run_test(yum_command), 'Error while getting repo info'

            if host.system_info.distribution != 'fedora':
                assert 'Repo-pkgs          : 0' not in host.check_output(yum_command), \
                    'Unexpected number of repo pkgs (0)'

    @pytest.mark.run_on(['rhel'])
    def test_yum_package_install(self, host):
        with host.sudo():
            if 'rhui' not in host.check_output('rpm -qa'):
                pytest.skip('Not applicable to non-RHUI images')

            assert \
                host.run('yum clean all') and \
                host.run_test('yum repolist'), \
                'Could not get repo list correctly'

            return_code = host.run('yum check-update').rc
            assert return_code == 0 or return_code == 100, \
                'Could not check for yum updates'

            assert \
                host.run_test('yum search zsh') and \
                host.run_test('yum -y install zsh') and \
                host.run_test(r"rpm -q --queryformat '%{NAME}' zsh") and \
                host.run_test('rpm -e zsh'), \
                'yum packages installation failed'


@pytest.mark.order(1)
class TestsNetworking:
    # TODO: redo test with test infra module
    @pytest.mark.run_on(['all'])
    def test_dns_resolving_works(self, host):
        """
        Check if DNS resolving works.
        """
        assert host.run_test('ping -c 5 google-public-dns-a.google.com'), \
            'Public DNS resolution did not work'

    @pytest.mark.run_on(['all'])
    def test_ipv_localhost(self, host):
        """
        Check that localhost ipv6 and ipv4 are set in /etc/hosts.
        """
        expected_hosts = ['127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4',
                          '::1         localhost localhost.localdomain localhost6 localhost6.localdomain6']
        with host.sudo():
            for expected_host in expected_hosts:
                assert host.file('/etc/hosts').contains(expected_host), \
                    '/etc/hosts does not contain ipv4 or ipv6 localhost'

    @pytest.mark.run_on(['rhel', 'fedora35', 'centos'])
    def test_eth0_network_adapter_setup(self, host):
        """
        Make sure that eht0 default adapter is correctly setup:
            1. NETWORKING=yes in /etc/sysconfig/network
            2. DEVICE=eth0 in /etc/sysconfig/network-scripts/ifcfg-eth0

        Does not apply to >fedora35: https://fedoramagazine.org/converting-networkmanager-from-ifcfg-to-keyfiles/
        """
        device_name = 'eth0'

        with host.sudo():
            assert host.file('/etc/sysconfig/network').contains('^NETWORKING=yes'), \
                'Invalid networking setup'

            device_config_path = f'/etc/sysconfig/network-scripts/ifcfg-{device_name}'

            assert host.file(device_config_path).contains(f'^DEVICE=[{device_name}|\"{device_name}\"]'), \
                f'Unexpected device name. Expected: "{device_name}"'

    @pytest.mark.run_on(['rhel'])
    @pytest.mark.exclude_on(['<rhel8.5'])
    def test_network_manager_cloud_setup(self, host, instance_data):
        """
        BugZilla 1822853
        >=8.5: check NetworkManager-cloud-setup is installed and nm-cloud-setup.timer is setup for Azure and enabled
        """
        cloud_setup_base_path = '/usr/lib/systemd/system/nm-cloud-setup.service.d/'
        files_and_configs_by_cloud = {
            'aws': {
                'file_to_check': os.path.join(cloud_setup_base_path, '10-rh-enable-for-ec2.conf'),
                'expect_configs': [
                    'Environment=NM_CLOUD_SETUP_EC2=yes',
                    'Environment="NM_CLOUD_SETUP_EC2=yes"'
                ]
            },
            'azure': {  # COMPOSER-842
                'file_to_check': os.path.join(cloud_setup_base_path, '10-rh-enable-for-azure.conf'),
                'expect_configs': [
                    'Environment=NM_CLOUD_SETUP_AZURE=yes',
                    'Environment="NM_CLOUD_SETUP_AZURE=yes"'
                ]
            }
        }

        # EXDSP-813
        if instance_data['cloud'] == 'azure' and \
                version.parse(host.system_info.release) == version.parse('8.5'):
            pytest.skip("There is a known issue affecting RHEL 8.5 on Azure images and won't be fixed (EXDSP-813).")

        with host.sudo():
            assert host.package('NetworkManager-cloud-setup').is_installed, \
                'NetworkManager-cloud-setup is expected to be installed in RHEL 8.5 and above'

            assert host.service('nm-cloud-setup').is_enabled, \
                'Expected cloud service is not enabled'

            file_to_check = files_and_configs_by_cloud[instance_data['cloud']]['file_to_check']
            expect_configs = files_and_configs_by_cloud[instance_data['cloud']]['expect_configs']

            res = []
            for cfg in expect_configs:
                res.append(host.file(file_to_check).contains(cfg))
            assert any(res), f'{expect_configs} config is not set'

    @pytest.mark.run_on(['rhel'])
    def test_network_manager_conf_plugins(self, host, instance_data):
        """
        Check /etc/NetworkManager/NetworkManager.conf
        JIRA: CLOUDX-488
        """
        if instance_data['cloud'] == 'gcloud':
            pytest.skip('This test does not apply to GCP.')

        cloud_init_version = host.package('cloud-init').version
        print(f'cloud-init version installed: cloud-init-{cloud_init_version}')

        # Stating from cloud-init-23.1.1, NetworkManager plugins are not forced via config by cloud-init.
        if cloud_init_version >= '23.1.1':
            pytest.skip(f'This test is not applicable starting from cloud-init-{cloud_init_version}')

        file_to_check = '/etc/NetworkManager/NetworkManager.conf'

        with host.sudo():
            grep_filter = r'\[main\]'
            print(f'{file_to_check} [main] section content (first two lines):')
            print(host.run(f'grep "{grep_filter}" -A2 {file_to_check}').stdout)

            cmd = 'NetworkManager --print-config'
            print(cmd)
            print(host.run(cmd).stdout)

            assert host.file(file_to_check).contains('^plugins = ifcfg-rh,$'), \
                f'Unexpected or missing plugin(s) in {file_to_check}'


@pytest.mark.order(1)
class TestsSecurity:
    @pytest.mark.run_on(['rhel'])
    def test_firewalld_is_enabled(self, host, instance_data):
        """
        firewalld needs to be enabled in most clouds.
        """
        if instance_data['cloud'] == 'aws':
            pytest.skip('Test not applicable to AWS images')

        assert host.service('firewalld').is_enabled, \
            'firewalld should be enabled in most RHEL cloud images (except AWS AMIs)'


@pytest.mark.order(1)
@pytest.mark.run_on(['rhel'])
class TestsAuthConfig:
    @pytest.fixture(autouse=True)
    def skip_on_aws(self, host, instance_data):
        if instance_data['cloud'] == 'aws':
            pytest.skip("Auth test cases don't apply to AWS.")

    @pytest.mark.exclude_on(['rhel7.9'])
    def test_authselect_has_no_config(self, host):
        """
        Check authselect current
        """
        expected_output = 'No existing configuration detected.'
        assert expected_output in host.run('authselect current').stdout, \
            'authselect is expected to have no configuration'

    @pytest.mark.exclude_on(['rhel7.9'])
    def test_authselect_conf_files(self, host):
        authselect_dir = '/etc/authselect/'
        expected_config_files = ['custom', 'user-nsswitch.conf']
        current_files = host.file(authselect_dir).listdir()

        print(current_files)

        assert current_files == expected_config_files, \
            f'Unexpected result when listing files under {authselect_dir}'

        authselect_custom_dir = '/etc/authselect/custom/'
        assert len(host.file(authselect_custom_dir).listdir()) == 0, \
            f'Unexpected files found under {authselect_custom_dir}.' \
            f'This directory should be empty'

    def test_fingerprint_auth(self, host):
        """
        Check file /etc/pam.d/fingerprint-auth
        """
        self.__check_pam_d_file_content(host, 'fingerprint-auth')

    def test_password_auth(self, host):
        """
        Check file /etc/pam.d/password-auth
        """
        self.__check_pam_d_file_content(host, 'password-auth')

    def test_postlogin(self, host):
        """
        Check file /etc/pam.d/postlogin
        """
        self.__check_pam_d_file_content(host, 'postlogin')

    @pytest.mark.jira_skip(['CLOUDX-511'])
    def test_smartcard_auth(self, host):
        """
        Check file /etc/pam.d/smartcard-auth
        Bugzilla: 1983683
        """

        self.__check_pam_d_file_content(host, 'smartcard-auth')

    def test_system_auth(self, host):
        """
        Check file /etc/pam.d/system-auth
        """
        self.__check_pam_d_file_content(host, 'system-auth')

    def __check_pam_d_file_content(self, host, file_name):
        system_release_major_version = version.parse(host.system_info.release).major
        local_file = f'data/generic/{file_name}_rhel{system_release_major_version}'
        file_to_check = f'/etc/pam.d/{file_name}'

        assert test_lib.compare_local_and_remote_file(host, local_file, file_to_check), \
            f'{file_to_check} has unexpected content'


@pytest.mark.order(3)
class TestsKdump:
    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    @pytest.mark.usefixtures('check_kdump_fix_condition')
    def test_kdump_status(self, host):
        """
        Verify that kdump is enabled

        Kdump contacts
        Devel: kasong@redhat.com, ruyang@redhat.com, piliu@redhat.com
        QE: xiawu@redhat.com
        """
        with host.sudo():
            kernel_version = host.check_output('uname -r').split("-")[0]

            print(f' - kexec-tools version: {host.run("rpm -qa | grep kexec-tools").stdout}')
            if 'Kdump is operational' not in host.run('kdumpctl status 2>&1').stdout:
                print(f' - kdumpctl showmem: {host.run("kdumpctl showmem").stdout}')
                print(f' - kernel version: {kernel_version}')
                print(f' - dmesg grep crashkernel: {host.run("dmesg | grep crashkernel").stdout}')
                print(f' - journalctl kdump service: {host.run("journalctl --no-pager -u kdump.service").stdout}')
                print(f' - journalctl kernel: {host.run("journalctl --no-pager -k").stdout}')
                pytest.fail('Kdump is not operational')


@pytest.mark.pub
@pytest.mark.run_on(['rhel8.10'])  # Let's update this list when there are more minor ELS GA releases (e.g. rhel-9.10 ?)
class TestsRhelEls:
    """
    A set of test cases that should only run if RHEL minor release is the last one and will enter into ELS mode.
    For example, for RHEL-8, the last minor release is RHEL-8.10, and there won't be any further minor releases for major version 8.
    """
    def test_rhui_pkg_is_not_e4s(self, host):
        """
        Make sure the RHUI package is not "e4s".
        """
        result = test_lib.print_host_command_output(host, 'rpm -qa | grep rhui', capture_result=True)

        assert 'e4s' not in result.stdout, f'RHUI package is E4S ({result.stdout})'

    def test_no_release_version_lock(self, host):
        """
        There that there is no release version lock in /etc/yum/vars/releasever or that file doesn't exist
        """
        file_to_check = '/etc/yum/vars/releasever'

        # Would it be easier if we check that the file is empty?
        version_lock = f'releasever={host.system_info.release}'

        if host.file(file_to_check).exists:
            assert not host.file(file_to_check).contains(version_lock), \
                f'{file_to_check} has a version lock.'

    def test_no_e4s_repo_definition(self, host):
        """
        Make sure the E4S repos are not included.
        """
        repos_dir = '/etc/yum.repos.d/'

        result = host.run_test(f'grep -r "e4s" {repos_dir}')

        # TODO: Add check
        assert result.failed, f'E4S references found in repository definitions:\n{repos_dir.stdout}'
