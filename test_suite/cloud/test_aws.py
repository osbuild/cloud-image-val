import json
import re

import pytest
from packaging import version

from lib import test_lib, aws_lib


@pytest.fixture
def instance_data_aws_web(host):
    return aws_lib.get_aws_instance_identity_from_web(host)


@pytest.fixture
def instance_data_aws_cli(host, instance_data_aws_web):
    query_to_run = 'Reservations[].Instances[]'

    command_to_run = [
        'aws ec2 describe-instances',
        '--instance-id {0}'.format(instance_data_aws_web['instanceId']),
        '--region {0}'.format(instance_data_aws_web['region']),
        f'--query "{query_to_run}"'
    ]

    result = host.backend.run_local(' '.join(command_to_run))

    if result.failed:
        raise Exception(f'The aws cli command "{command_to_run}" exited with {result.exit_status}. '
                        f'Output: {result.stdout} '
                        f'Error: {result.stderr}')

    return json.loads(result.stdout)[0]


@pytest.mark.order(2)
class TestsAWS:
    @pytest.mark.pub
    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_ami_name(self, host, instance_data):
        """Validates AMI naming conventions based on distribution and type.

        - all RHEL: Must contain 'RHEL'.
        - RHEL SAP: Must not contain 'Access2' and include 'SAP'.
        - RHEL HA: Must include 'HA' and not be ARM ('arm64' in name or aarch64 arch).
        - Fedora: Must follow Fedora Cloud-Base naming format.
        """
        distro = host.system_info.distribution
        ami_name = instance_data['name']

        if distro == 'rhel':
            assert 'RHEL' in ami_name, \
                "AMI name for RHEL image must contain 'RHEL'."

            if test_lib.is_rhel_saphaus(host):
                assert 'SAP' in ami_name, \
                    "AMI name for RHEL for SAP with HA and US image must contain 'SAP'."
                assert 'Access2' not in ami_name, \
                    "SAP AMI name must not contain 'Access2' (RHELDST-4739)."

            if test_lib.is_rhel_high_availability(host):
                assert 'HA' in ami_name, \
                    "AMI name for RHEL High Availability image must contain 'HA'."
                assert host.system_info.arch != 'aarch64' and 'arm64' not in ami_name, \
                    f"RHEL High Availability AMI on architecture '{host.system_info.arch}' " \
                    "does not support ARM (aarch64/arm64) architectures."

        elif distro == 'fedora':
            fedora_ami_name_format = re.compile(
                r'Fedora-Cloud-Base-[\d]{2}-[\d]{8}.n.[\d].(?:aarch64|x86_64)')
            assert re.match(fedora_ami_name_format, ami_name), \
                "AMI name for Fedora image does not follow the expected Cloud-Base format."

    @pytest.mark.pub
    @pytest.mark.run_on(['all'])
    def test_release_version_in_ami_name(self, host, instance_data):
        """
        Verify the major-minor release version is present in the AMI name.
        """
        ami_name = instance_data['name']
        system_release = float(host.system_info.release)

        assert str(system_release).replace('.', '-') in ami_name, \
            'System release not found in AMI name'

    @pytest.mark.run_on(['rhel'])
    def test_iommu_strict_mode(self, host):
        """
        Use "iommu.strict=0" in ARM AMIs to get better performance.
        BugZilla 1836058
        """
        option = 'iommu.strict=0'

        with host.sudo():
            iommu_option_present = host.file('/proc/cmdline').contains(option)

            if host.system_info.arch == 'x86_64':
                assert not iommu_option_present, f'{option} must not be present in x86_64 AMIs'
            else:
                assert iommu_option_present, f'{option} must be present in ARM AMIs'

    @pytest.mark.run_on(['rhel'])
    def test_unwanted_packages_are_not_present(self, host):
        """
        Some pkgs are not required in EC2.
        BugZilla 2075815
        """
        unwanted_pkgs = [
            'aic94xx-firmware', 'alsa-firmware', 'alsa-lib', 'alsa-tools-firmware',
            'ivtv-firmware', 'iwl1000-firmware', 'iwl100-firmware', 'iwl105-firmware',
            'iwl135-firmware', 'iwl2000-firmware', 'iwl2030-firmware', 'iwl3160-firmware',
            'iwl3945-firmware', 'iwl4965-firmware', 'iwl5000-firmware', 'iwl5150-firmware',
            'iwl6000-firmware', 'iwl6000g2a-firmware', 'iwl6000g2b-firmware', 'iwl6050-firmware',
            'iwl7260-firmware', 'libertas-sd8686-firmware', 'libertas-sd8787-firmware', 'libertas-usb8388-firmware',
            'firewalld', 'biosdevname', 'plymouth', 'iprutils'
        ]

        if test_lib.is_rhel_saphaus(host):
            # In RHEL SAP images, alsa-lib is allowed
            unwanted_pkgs.remove('alsa-lib')

        if test_lib.is_rhel_high_availability(host):
            unwanted_pkgs.append('rh-amazon-rhui-client')

        found_pkgs = []
        with host.sudo():
            for pkg in unwanted_pkgs:
                if host.package(pkg).is_installed:
                    found_pkgs.append(pkg)
                    print(host.check_output(f'rpm -q {pkg}'))

        assert len(found_pkgs) == 0, f'Found unexpected packages installed: {", ".join(found_pkgs)}'

    # TODO: Refactor this test case. E.g. divide it by type of image and version
    @pytest.mark.run_on(['rhel'])
    def test_required_packages_are_installed(self, host):
        """
        Some pkgs are required in EC2.
        https://kernel.googlesource.com/pub/scm/boot/dracut/dracut/+/18e61d3d41c8287467e2bc7178f32d188affc920%5E!/

        dracut-nohostonly -> dracut-config-generic
        dracut-norescue   -> dracut

        BugZilla 1822853, 1823315: Starting from RHEL 8.5, NetworkManager-cloud-setup package was added
        """
        required_pkgs = [
            'kernel', 'yum-utils', 'redhat-release', 'redhat-release-eula',
            'cloud-init', 'tar', 'rsync', 'dhcp-client', 'NetworkManager',
            'cloud-utils-growpart', 'gdisk', 'insights-client',
            'dracut-config-generic', 'grub2-tools',
        ]

        system_release = version.parse(host.system_info.release)
        if system_release >= version.parse('8.5'):
            required_pkgs.append('NetworkManager-cloud-setup')

        # CLOUDX-451
        if system_release.major == 9 and system_release.minor >= 3 or \
                system_release.major == 8 and system_release.minor >= 9:
            if host.system_info.arch != 'aarch64':
                # Legacy BIOS boot mode related package
                required_pkgs.append('grub2-pc')

                # UEFI boot mode related packages, not applicable to arm64 AMIs
                required_pkgs.extend(['efibootmgr', 'grub2-efi-x64', 'shim-x64'])

        # RHELMISC-4466 dhcp-client retired in RHEL10
        # RHELMISC-6651 gdisk retired in RHEL10
        if system_release.major >= 10:
            required_pkgs.remove('dhcp-client')
            required_pkgs.remove('gdisk')

        if test_lib.is_rhel_high_availability(host):
            required_pkgs.extend(['fence-agents-all', 'pacemaker', 'pcs'])

        missing_pkgs = [pkg for pkg in required_pkgs if not host.package(pkg).is_installed]

        assert len(missing_pkgs) == 0, f'Missing packages: {", ".join(missing_pkgs)}'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_rhui_pkg_is_installed(self, host):
        with host.sudo():
            # CLOUDX-590
            if host.run('rm -f /var/lib/rpm/__db.*').failed or host.run('rpm --rebuilddb').failed:
                change_permissions_cmd = 'chmod 755 /var/lock /var/lock/rpm ' \
                                         '&& chown root.lock /var/lock ' \
                                         '&& chown root.root /var/lock/rpm'
                assert host.run_test(change_permissions_cmd), 'Failed to change permissions'
                if host.file('/var/lock/rpm/transaction').exists:
                    assert host.run_test('rm -f /var/lock/rpm/transaction'), 'Failed to remove the transaction file'

        unwanted_rhui_pkgs = None

        if test_lib.is_rhel_high_availability(host):
            required_rhui_pkg = 'rh-amazon-rhui-client-ha'
        elif test_lib.is_rhel_saphaus(host):
            required_rhui_pkg = 'rh-amazon-rhui-client-sap-bundle'
        else:
            required_rhui_pkg = 'rh-amazon-rhui-client'
            unwanted_rhui_pkgs = [
                'rh-amazon-rhui-client-ha',
                'rh-amazon-rhui-client-sap',
            ]

        test_lib.print_host_command_output(host, 'rpm -qa | grep rhui')

        if unwanted_rhui_pkgs:
            for pkg in unwanted_rhui_pkgs:
                assert host.run(f'rpm -qa | grep {pkg}').failed, \
                    f'Unexpected rhui package installed: {pkg}'

        assert host.run(f'rpm -qa | grep {required_rhui_pkg}').succeeded, \
            f'Package "{required_rhui_pkg}" should be present'

    @pytest.mark.run_on(['rhel'])
    def test_amazon_timesync_service_is_used(self, host):
        """
        BugZilla 1679763, 1961156
        """
        timesync_service_ipv4 = '169.254.169.123'
        line = f'server {timesync_service_ipv4} iburst minpoll 4 maxpoll 4'
        compatible_version = 7.8

        with host.sudo():
            chrony_conf_content = host.file('/etc/chrony.conf').content_string

            assert line not in chrony_conf_content, \
                f'"{line}" must be enabled in RHEL {compatible_version} and above'

            assert f'Selected source {timesync_service_ipv4}' in host.check_output('journalctl -u chronyd'), \
                'Amazon Time Sync service is not in use'

    @pytest.mark.run_on(['rhel'])
    def test_max_cstate_is_configured_in_cmdline(self, host):
        """
        Check that intel_idle.max_cstate=1 processor.max_cstate=1 exists in SAP AMI's /proc/cmdline.
        BugZilla 1961225
        """
        cstate_setting_lines = [
            'intel_idle.max_cstate=1',
            'processor.max_cstate=1',
        ]

        with host.sudo():
            for line in cstate_setting_lines:
                if test_lib.is_rhel_saphaus(host):
                    assert host.file('/proc/cmdline').contains(line), \
                        f'{line} must be specified in SAP AMIs'
                else:
                    assert not host.file('/proc/cmdline').contains(line), \
                        f'{line} must not be specified in AMIs that are not SAP'

    @pytest.mark.run_on(['all'])
    def test_hostkey_permissions(self, host):
        """
        Check that ssh files permission set are correct.
        BugZilla 2013644
        Ensure permissions are aligned with a distro and release version
        CLOUDX-994
        """
        files_to_check = ['ssh_host_ecdsa_key',
                          'ssh_host_ed25519_key', 'ssh_host_rsa_key']

        # Default permission for private keys
        expected_mode = 0o640
        distro = host.system_info.distribution
        release_major = version.parse(host.system_info.release).major

        if distro == 'centos' and release_major == 9:
            expected_mode = 0o600

        if distro == 'fedora' or \
           ((distro == 'rhel' or distro == 'centos') and release_major == 10):
            # Strict permissions
            expected_mode = 0o600

        print(host.run('rpm -q cloud-init').stdout)

        for file in files_to_check:
            print(host.run(f'stat -c "%a %n" /etc/ssh/{file}*').stdout)
            if host.file(f'/etc/ssh/{file}').exists:
                assert host.file(f'/etc/ssh/{file}').mode == expected_mode, \
                    'ssh files permissions are not set correctly'

    @pytest.mark.run_on(['rhel'])
    def test_aws_instance_identity(self, host, instance_data, instance_data_aws_web):
        """
        Try to fetch instance identity from EC2 and compare with expectation
        """
        assert instance_data_aws_web['imageId'] == instance_data['image'], \
            'Unexpected AMI ID for deployed instance'

        assert instance_data_aws_web['region'] in instance_data['availability_zone'], \
            'Unexpected region for deployed instance'

        arch = instance_data_aws_web['architecture']
        if arch == 'arm64':
            arch = 'aarch64'

        assert arch == host.system_info.arch, \
            'Unexpected architecture for deployed instance'

        ami_name = instance_data['name']

        billing_codes = []
        if test_lib.is_rhel_high_availability(host) and 'Access2' not in ami_name:
            # RHELDST-4222, on-demand (hourly) has the billing code for RHEL and for HA
            billing_codes = ['bp-79a54010', 'bp-6fa54006']
        elif 'Hourly2' in ami_name:
            billing_codes = ['bp-6fa54006']
        elif 'Access2' in ami_name:
            # Cloud Access billing code, means don't charge for the OS (so it can apply to anything cloud Access)
            billing_codes = ['bp-63a5400a']
        else:
            pytest.skip(
                'Unable to decide billing codes as no "Hourly2" or "Access2" found in AMI name')

        for code in billing_codes:
            assert code in instance_data_aws_web['billingProducts'], \
                'Expected billing code not found in instance document data'

    @pytest.mark.run_on(['rhel'])
    def test_cmdline_nvme_io_timeout(self, host):
        """
        Check if default value of /sys/module/nvme_core/parameters/io_timeout is set to 4294967295.
        BugZilla 1732506
        """
        expected_value = '4294967295'

        with host.sudo():
            assert host.file('/proc/cmdline').contains(f'nvme_core.io_timeout={expected_value}'), \
                f'nvme_core.io_timeout should be set to {expected_value}'

        if 'nvme' in host.check_output('lsblk'):
            assert host.file('/sys/module/nvme_core/parameters/io_timeout').contains(expected_value), \
                f'Actual value in io_timeout is not {expected_value}'

    @pytest.mark.run_on(['rhel'])
    def test_ena_support_correctly_set(self, host, instance_data_aws_cli):
        """
        Check that Elastic Network Adapter support is enabled.
        """
        ena_support = bool(instance_data_aws_cli['EnaSupport'])

        assert ena_support, \
            'ENA support expected to be enabled in RHEL 7.4 and later'

    @pytest.mark.run_on(['rhel'])
    def test_yum_plugins(self, host):
        """
        BugZilla 1932802
        Verify yum/dnf product-id and subscription-manager plugins are enabled for RHEL 8.4+.
        """
        expect_config = "enabled=1"

        with host.sudo():
            assert host.file('/etc/yum/pluginconf.d/product-id.conf').contains(expect_config), \
                'yum "product-id" plugin must be enabled'

            assert host.file('/etc/yum/pluginconf.d/subscription-manager.conf').contains(expect_config), \
                'yum "subscription-manager" must be enabled'

    @pytest.mark.run_on(['<rhel10'])
    def test_dracut_conf_sgdisk(self, host):
        """
        Enable resizing on copied AMIs, added 'install_items+=" sgdisk "' to "/etc/dracut.conf.d/sgdisk.conf"
        JIRA: CLOUDX-373
        """
        assert host.package('gdisk').is_installed, 'Package "gdisk" is expected to be installed'

        # Before RHEL 8.5, AMIs were built using ks file. So the path is different.
        files_to_check = [
            '/etc/dracut.conf.d/sgdisk.conf',
            '/usr/lib/dracut/dracut.conf.d/sgdisk.conf'
        ]

        with host.sudo():
            test_lib.print_host_command_output(host, 'ls -R /etc/dracut* /usr/lib/dracut/dracut*')

            file_found = False
            config_ok = False

            for file in files_to_check:
                if host.file(file).exists:
                    file_found = True
                    test_lib.print_host_command_output(host, f'cat {file}')

                    if host.file(file).contains('install_items+=" sgdisk "'):
                        config_ok = True

        assert file_found, 'sgdisk.conf file not found.'
        assert config_ok, 'Expected configuration was not found in sgdisk.conf'

    @pytest.mark.run_on(['rhel'])
    def test_dracut_conf_xen(self, host):
        """
        BugZilla 1849082
        JIRA COMPOSER-1096
        Add ' xen-netfront xen-blkfront ' to '/etc/dracut.conf.d/xen.conf' in x86 AMIs prior RHEL-8.4.
        Using image builder from RHEL-8.5, add ' nvme xen-blkfront ' to '/usr/lib/dracut/dracut.conf.d/ec2.conf'.
        This is not required in arm AMIs.
        """
        file_to_check = '/usr/lib/dracut/dracut.conf.d/ec2.conf'
        expected_config = ' nvme xen-blkfront '

        with host.sudo():
            if host.system_info.arch == 'aarch64':
                assert not host.file(file_to_check).exists, \
                    f'Unexpected configuration file found: "{file_to_check}".'
            else:
                assert host.file(file_to_check).contains(expected_config), \
                    f'Expected configuration was not found in "{file_to_check}"'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    @pytest.mark.usefixtures('rhel_aws_marketplace_only')
    def test_yum_group_install(self, host):
        """
        Test that the "Development tools" package group can be successfully installed.

        This test verifies system package management functionality by attempting to install
        the Development tools group, which contains essential packages for software development
        like gcc, make, and glibc-devel.

        The test also validates RPM database health before installation and handles known
        subscription manager issues that may interfere with package installation.

        Failure of this test indicates system-level issues such as:
        - RPM database corruption
        - Repository configuration problems
        - RHUI content availability issues
        - Subscription management issues
        - Package dependency conflicts
        """
        with host.sudo():
            # Assert RPM database health before attempting installation
            rpm_check = host.run('rpm --verifydb')
            assert rpm_check.succeeded, \
                f'RPM database is corrupted or inaccessible. Error: {rpm_check.stderr}. ' \
                'This is a system-level issue that must be resolved.'

            dev_tools_install_command = 'yum -y groupinstall "Development tools"'
            result = host.run(dev_tools_install_command)

            if result.failed:
                print(f'Command failed with error on first attempt: {result.stderr}')
                err_message = "This system is not registered to Red Hat Subscription Management"
                if err_message in result.stderr:
                    print('"Development tools" installation failed. Applying a workaround...')
                    workaround_result = host.run(
                        'echo -e "enabled=0" > /etc/yum/pluginconf.d/subscription-manager.conf'
                        ' && yum clean all'
                    )

                    if workaround_result.failed:
                        print(f'Workaround failed: {workaround_result.stderr}')

                    retry_result = host.run(dev_tools_install_command)
                    assert retry_result.succeeded, (
                        'Error while installing Development tools group after two attempts.\n'
                        f'First attempt error: {result.stderr}\n'
                        f'Retry attempt error: {retry_result.stderr}'
                    )
                else:
                    # If it's not a subscription issue, fail immediately with detailed info
                    assert result.succeeded, (
                        'Development tools installation failed with unexpected error: '
                        f'{result.stderr}\n'
                        'Possible repository configuration or RHUI content availability issues.'
                    )

            # Verify installation with multiple key packages from Development tools group
            essential_dev_packages = [
                'gcc',           # C compiler
                'gcc-c++',       # C++ compiler
                'glibc-devel',   # C library development files
                'make',          # Build automation tool
                'pkgconf'        # Package configuration tool (replaces pkg-config in newer RHEL)
            ]

            # Check what Development tools packages are actually installed
            print('Verifying Development tools packages installation...')
            test_lib.print_host_command_output(
                host, 'rpm -qa | grep -E "(gcc|glibc-devel|make|pkgconf)" | sort')

            missing_packages = []
            for package in essential_dev_packages:
                if not host.package(package).is_installed:
                    missing_packages.append(package)

            # Provide detailed failure information if packages are missing
            if missing_packages:
                print('Missing essential Development tools packages: '
                      f'{", ".join(missing_packages)}')

                # Show what was actually installed vs what was expected
                test_lib.print_host_command_output(host, 'yum history list | head -10')
                test_lib.print_host_command_output(host, 'rpm -qa | grep -i devel | wc -l')

                # Check if this might be an RPM database issue
                rpm_verify = host.run('rpm -V glibc-devel 2>/dev/null')
                if rpm_verify.failed:
                    print('RPM verification failed - possible database corruption')

                assert False, (
                    'Development tools group installation appeared to succeed, '
                    f'but essential packages are missing: {", ".join(missing_packages)}. '
                    'This may indicate RPM database issues or incomplete group installation.'
                )

    @pytest.mark.run_on(['all'])
    def test_number_of_cpus_are_correct(self, host, instance_data_aws_cli):
        """
        Check that the number of cpu cores available match the cpus obtained from AWS instance data
        """

        with host.sudo():
            cpu_cores = int(host.check_output(
                'grep "^processor" /proc/cpuinfo | wc -l'))

        aws_cli_cup_data = instance_data_aws_cli['CpuOptions']

        total_v_cpus = aws_cli_cup_data['CoreCount'] * aws_cli_cup_data['ThreadsPerCore']

        assert total_v_cpus == cpu_cores

    @pytest.mark.pub
    @pytest.mark.run_on(['all'])
    def test_number_gpg_keys(self, host):
        """
        Check that the number of GPGs is correct
        """
        with host.sudo():
            # print the gpg public keys installed
            print(host.check_output('rpm -qa | grep gpg-pubkey'))

            if host.system_info.distribution == 'fedora':
                num_of_gpg_keys = 1
            elif host.system_info.distribution == 'rhel' and \
                    version.parse(host.system_info.release) >= version.parse('9.0'):
                num_of_gpg_keys = 3
            else:
                num_of_gpg_keys = 2

        # check correct number of gpg keys installed
        assert int(host.check_output('rpm -q gpg-pubkey | wc -l')) == num_of_gpg_keys, \
            f'There should be {num_of_gpg_keys} gpg key(s) installed'

    @pytest.mark.run_on(['rhel'])
    def test_hybrid_boot_mode_config(self, host):
        """
        Check that hybrid boot mode is correctly configured. Only applicable to x86_64 AMIs.
        JIRA: COMPOSER-1851
        """
        if host.system_info.arch == 'aarch64':
            pytest.skip('Hybrid boot mode is only available in x86_64 AMIs.')

        path_to_check = '/sys/firmware/efi'

        system_release = version.parse(host.system_info.release)
        if system_release.major == 9 and system_release.minor >= 3 or \
                system_release.major == 8 and system_release.minor >= 9:
            with host.sudo():
                assert host.file(path_to_check).exists, \
                    f'{path_to_check} is expected to exist in EFI-booted images.'

                result = host.run('efibootmgr 2>&1')
                if result.exit_status != 0:
                    print(result.stdout)
                    pytest.fail('efibootmgr command failed in EFI-booted image.')
        else:
            pytest.skip('This test case is only applicable to RHEL-8.9+ and RHEL-9.3+.')


@pytest.mark.order(2)
class TestsAWSNetworking:
    @pytest.mark.run_on(['all'])
    def test_correct_network_driver_is_used(self, host):
        """
        If ena network device found, eth0 should use ena as default driver.
        If vf network device found, eth0 should use ixgbevf as default driver.
        If others, eth0 should use vif as default driver.
        If it is not a xen instance, ena should be used.
        """
        with host.sudo():
            if host.system_info.distribution == 'fedora':
                host.run_test('dnf install lshw -y >/dev/null')

            nic_name = host.check_output('lshw -C network')
            nic_driver = host.check_output('lshw -C network | grep "driver="')

            self.__test_nic_is_using_correct_driver(nic_name, nic_driver)

            if 'Xen' not in host.check_output('lscpu'):
                assert 'ena' in nic_driver, 'ENA driver must de used in KVM, arch64 and metal instances'

    def __test_nic_is_using_correct_driver(self, nic_name, nic_driver):
        name_filter, driver_filter = self.__get_nic_filters_for_drivers(
            nic_name)

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

    @pytest.mark.run_on(['all'])
    def test_network_ipv6_setup(self, host):
        """
        Check for IPv6 networking setup.
        """
        mac_addresses_url = 'http://169.254.169.254/latest/meta-data/network/interfaces/macs'
        registered_mac_address = host.check_output(
            f'curl -s {mac_addresses_url}').replace('/', '')
        registered_ipv6 = host.check_output(
            f'curl -s {mac_addresses_url}/{registered_mac_address}/ipv6s')

        if 'Not Found' in registered_ipv6:
            pytest.skip('No IPv6 enabled in this Subnet')

        assert registered_ipv6 in host.interface('eth0', 'inet6').addresses, \
            f'Expected IPv6 {registered_ipv6} is not being used by eth0 network adapter'

    @pytest.mark.run_on(['rhel'])
    def test_redhat_cds_hostnames(self, host, instance_data_aws_web):
        """
        Check all Red Hat CDS for the AMI's instance region.
        """
        region = instance_data_aws_web['region']

        rhui_cds_hostnames = [
            f'rhui.{region}.aws.ce.redhat.com',
            f'rhui4-cds01.{region}.aws.ce.redhat.com',
            f'rhui4-cds02.{region}.aws.ce.redhat.com',
        ]

        with host.sudo():
            for cds in rhui_cds_hostnames:
                # There is no rhui in us-gov regions at all.
                # All the content requests are redirected to the closest standard regions.
                cds_name = cds.replace('-gov', '')

                cds_list_with_errors = []
                if host.run(f'getent hosts {cds_name}').exit_status != 0:
                    cds_list_with_errors.append(cds)

        print('Red Hat CDS hosts possibly unreachable or with issues:')
        print('\n'.join(cds_list_with_errors))

        assert len(cds_list_with_errors) < len(rhui_cds_hostnames), \
            'None of the CDS are reachable or all of them have issues'


class TestsAWSSecurity:
    @pytest.mark.run_on(['rhel'])
    def test_firewalld_is_not_installed(self, host):
        """
        firewalld is not required in AWS because there are other security mechanisms.
        """
        assert not host.package('firewalld').is_installed, \
            'firewalld should not be installed in RHEL AMIs'
