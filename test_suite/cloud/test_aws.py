import json
import re

import pytest
from packaging import version

from lib import test_lib


@pytest.fixture
def instance_data_aws_web(host):
    instance_document_url = 'http://169.254.169.254/latest/dynamic/instance-identity/document'
    return json.loads(host.check_output(f'curl -s {instance_document_url}'))


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
    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_etc_machine_id_permissions(self, host, instance_data):
        """
        Check that /etc/machine-id permissions are 444.
        Bugzilla: 2221269
        """
        assert host.file('/etc/machine-id').mode == 0o444, 'Expected 444 permissions for /etc/machine-id'

    # TODO: Divide test. Analyze centos
    @pytest.mark.pub
    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_ami_name(self, host, instance_data):
        """
        Check there is 'RHEL' in RHEL AMIs.
        In the case of Red Hat SAP AMIs, check that they do not contain "Access2" in the AMI name.
        In the case of Red Hat High Availability AMIs, check that they are not ARM and the name does not contain "arm64"
        In the case of Fedora AMIs, check that it follows the right Fedora Cloud-Base name format.
        """
        distro = host.system_info.distribution
        ami_name = instance_data['name']

        if distro == 'rhel':
            assert 'RHEL' in ami_name, 'Expected "RHEL" in AMI name for Red Hat image'

            if test_lib.is_rhel_sap(host):
                assert 'SAP' in ami_name, 'Expected "SAP" in Red Hat SAP AMI name'
                assert 'Access2' not in ami_name, \
                    'The Access2 images are not needed for this SAP image set (RHELDST-4739)'

            if test_lib.is_rhel_high_availability(host):
                assert 'HA' in ami_name, 'Expected "HA" in Red Hat High Availability AMI name'
                assert host.system_info.arch != 'aarch64' and 'arm64' not in ami_name, \
                    'ARM (aarch64/arm64) is not supported in Red Hat High Availability images'

        elif distro == 'fedora':
            fedora_ami_name_format = re.compile(
                r'Fedora-Cloud-Base-[\d]{2}-[\d]{8}.n.[\d].(?:aarch64|x86_64)')
            assert re.match(fedora_ami_name_format, ami_name), \
                'Unexpected AMI name for Fedora image'

    @pytest.mark.pub
    @pytest.mark.run_on(['all'])
    def test_release_version_in_ami_name(self, host, instance_data):
        """
        Check if release version is on the AMI name
        """
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('This test does not apply to Atomic AMIs')

        cloud_image_name = instance_data['name']
        product_version = float(host.system_info.release)

        assert str(product_version).replace('.', '-') in cloud_image_name, \
            'Product version is not in AMI name'

    # TODO: verify logic, think if we should divide
    @pytest.mark.run_on(['rhel'])
    def test_auditd(self, host):
        """
        - Service should be running
        - Config files should have the correct MD5 checksums
        """
        checksums_by_version = {
            '9.4+': {
                '/etc/audit/auditd.conf': 'fd5c639b8b1bd57c486dab75985ad9af',
                '/etc/audit/audit.rules': '795528bd4c7b4131455c15d5d49991bb'
            },
            '8.10+': {
                '/etc/audit/auditd.conf': 'fd5c639b8b1bd57c486dab75985ad9af',
                '/etc/audit/audit.rules': '795528bd4c7b4131455c15d5d49991bb'
            },
            '8.6+': {
                '/etc/audit/auditd.conf': 'f87a9480f14adc13605b7b14b7df7dda',
                '/etc/audit/audit.rules': '795528bd4c7b4131455c15d5d49991bb'
            },
            '8.0+': {
                '/etc/audit/auditd.conf': '7bfa16d314ddb8b96a61a7f617b8cca0',
                '/etc/audit/audit.rules': '795528bd4c7b4131455c15d5d49991bb'
            },
            '7.0+': {
                '/etc/audit/auditd.conf': '29f4c6cd67a4ba11395a134cf7538dbd',
                '/etc/audit/audit.rules': 'f1c2a2ef86e5db325cd2738e4aa7df2c'
            }
        }

        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not applicable to Atomic hosts')

        auditd_service = 'auditd'

        assert host.service(
            auditd_service).is_running, f'{auditd_service} expected to be running'

        system_release = version.parse(host.system_info.release)
        if system_release >= version.parse('9.4'):
            checksums = checksums_by_version['9.4+']
        elif version.parse('9.0') > system_release >= version.parse('8.10'):
            checksums = checksums_by_version['8.10+']
        elif system_release >= version.parse('8.6'):
            checksums = checksums_by_version['8.6+']
        elif system_release >= version.parse('8.0'):
            checksums = checksums_by_version['8.0+']
        else:
            checksums = checksums_by_version['7.0+']

        with host.sudo():
            for path, md5 in checksums.items():
                assert md5 in host.check_output(
                    f'md5sum {path}'), f'Unexpected checksum for {path}'

    @pytest.mark.run_on(['rhel'])
    def test_rh_cloud_firstboot_service_is_disabled(self, host):
        """
        Check that rh-cloud-firstboot is disabled.
        """
        if host.check_output('systemctl status rh-cloud-firstboot || echo false') != 'false':
            assert not host.service('rh-cloud-firstboot').is_enabled, \
                'rh-cloud-firstboot service must be disabled'

            with host.sudo():
                cloud_firstboot_file = host.file(
                    '/etc/sysconfig/rh-cloud-firstboot')
                # TODO: Confirm if test should fail when this file does not exist
                if cloud_firstboot_file.exists:
                    assert cloud_firstboot_file.contains('RUN_FIRSTBOOT=NO'), \
                        'rh-cloud-firstboot must be configured with RUN_FIRSTBOOT=NO'

    @pytest.mark.run_on(['rhel8.5', 'rhel8.6', 'rhel9.0'])
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
    @pytest.mark.exclude_on(['<rhel8.5'])
    def test_blocklist(self, host):
        """
        Check that a list of modules are disabled - not loaded.
        """
        modules = ['nouveau', 'amdgpu']
        blocklist_conf = '/usr/lib/modprobe.d/blacklist-{module}.conf'
        files_to_check = [blocklist_conf.format(module=modules[x]) for x in range(len(modules))]
        blocklist_conf_strings = ['blacklist ' + x for x in modules]

        with host.sudo():
            for module in modules:
                assert not host.run(f'lsmod | grep {module}').stdout, \
                    f"{module} shouldn't be loaded"

            for file, str_to_check in zip(files_to_check, blocklist_conf_strings):
                assert host.file(file).exists, f'file "{file}" does not exist'
                assert host.file(file).contains(str_to_check), \
                    f'{str_to_check} is not blocklisted in "{file}"'

    @pytest.mark.run_on(['rhel'])
    def test_unwanted_packages_are_not_present(self, host):
        """
        Some pkgs are not required in EC2.
        BugZilla 1888695, 2075815
        """
        unwanted_pkgs = [
            'aic94xx-firmware', 'alsa-firmware', 'alsa-lib', 'alsa-tools-firmware',
            'ivtv-firmware', 'iwl1000-firmware', 'iwl100-firmware', 'iwl105-firmware',
            'iwl135-firmware', 'iwl2000-firmware', 'iwl2030-firmware', 'iwl3160-firmware',
            'iwl3945-firmware', 'iwl4965-firmware', 'iwl5000-firmware', 'iwl5150-firmware',
            'iwl6000-firmware', 'iwl6000g2a-firmware', 'iwl6000g2b-firmware', 'iwl6050-firmware',
            'iwl7260-firmware', 'libertas-sd8686-firmware', 'libertas-sd8787-firmware', 'libertas-usb8388-firmware',
            'firewalld', 'biosdevname', 'plymouth', 'iprutils', 'rng-tools', 'qemu-guest-agent'
        ]

        system_release = version.parse(host.system_info.release)

        # BugZilla 1888695
        if version.parse('8.3') > system_release >= version.parse('8.0'):
            unwanted_pkgs.remove('rng-tools')

        if system_release < version.parse('8.5'):
            unwanted_pkgs.remove('qemu-guest-agent')

        if test_lib.is_rhel_sap(host):
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

        required_pkgs_v7 = [
            'kernel', 'yum-utils', 'cloud-init', 'dracut-config-generic',
            'grub2', 'tar', 'rsync', 'chrony'
        ]

        system_release = version.parse(host.system_info.release)
        if system_release >= version.parse('8.5'):
            required_pkgs.append('NetworkManager-cloud-setup')

        if version.parse('8.3') > system_release >= version.parse('8.0'):
            required_pkgs.append('rng-tools')

        # CLOUDX-451
        if system_release.major == 9 and system_release.minor >= 3 or \
                system_release.major == 8 and system_release.minor >= 9:
            if host.system_info.arch != 'aarch64':
                # Legacy BIOS boot mode related package
                required_pkgs.append('grub2-pc')

                # UEFI boot mode related packages, not applicable to arm64 AMIs
                required_pkgs.extend(['efibootmgr', 'grub2-efi-x64', 'shim-x64'])

        if test_lib.is_rhel_high_availability(host):
            required_pkgs.extend(['fence-agents-all', 'pacemaker', 'pcs'])

        if system_release < version.parse('8.0'):
            required_pkgs = required_pkgs_v7

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
        elif test_lib.is_rhel_sap(host):
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
    @pytest.mark.exclude_on(['<rhel8.5'])
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
                if test_lib.is_rhel_sap(host):
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
        """
        files_to_check = ['ssh_host_ecdsa_key',
                          'ssh_host_ed25519_key', 'ssh_host_rsa_key']
        expected_mode = 0o640
        if host.system_info.distribution == 'fedora' and \
                version.parse(host.system_info.release) >= version.parse('38'):
            # On Fedora 38, ssh_keys group no longer exists and ssh-keygen no longer chmods to 640, see
            # - https://src.fedoraproject.org/rpms/openssh/c/b615362fd0b4da657d624571441cb74983de6e3f?branch=rawhide
            # - https://src.fedoraproject.org/rpms/openssh/c/7a21555354a2c5e724aa4c287b640c24bf108780?branch=rawhide
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
    def test_cmdline_ifnames(self, host):
        """
        BugZilla 1859926
        ifnames should be specified
        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
        """
        with host.sudo():
            assert host.file('/proc/cmdline').contains('net.ifnames=0'), \
                'ifnames expected to be specified'

    @pytest.mark.run_on(['rhel'])
    def test_libc6_xen_conf_file_does_not_exist(self, host):
        """
        Check for /etc/ld.so.conf.d/libc6-xen.conf absence on RHEL
        """
        with host.sudo():
            file_to_check = '/etc/ld.so.conf.d/libc6-xen.conf'
            assert not host.file(
                file_to_check).exists, f'{file_to_check} should not be present in AMI'

    @pytest.mark.run_on(['rhel'])
    def test_ena_support_correctly_set(self, host, instance_data_aws_cli):
        """
        Check that Elastic Network Adapter support is enabled or disabled accordingly.
        """
        ena_support = bool(instance_data_aws_cli['EnaSupport'])

        if version.parse(host.system_info.release) < version.parse('7.4'):
            assert not ena_support, \
                'ENA support expected to be disabled in RHEL older than 7.4'
        else:
            assert ena_support, \
                'ENA support expected to be enabled in RHEL 7.4 and later'

    @pytest.mark.run_on(['rhel'])
    def test_yum_plugins(self, host):
        """
        BugZilla 1932802
        Earlier than RHEL-8.4, yum plugin product-id and subscription-manager should be disabled by default.
        """
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not applicable to RHEL Atomic Host AMIs')

        if version.parse(host.system_info.release) < version.parse('8.4'):
            expect_config = "enabled=0"
        else:
            expect_config = "enabled=1"

        with host.sudo():
            assert host.file('/etc/yum/pluginconf.d/product-id.conf').contains(expect_config), \
                'Unexpected yum "product-id" plugin status'

            assert host.file('/etc/yum/pluginconf.d/subscription-manager.conf').contains(expect_config), \
                'Unexpected yum "subscription-manager" plugin status'

    @pytest.mark.run_on(['rhel'])
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

    @pytest.mark.run_on(['rhel8.5', 'rhel8.6', 'rhel9.0'])
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
                    f'Unexpected configuration file found in "{file_to_check}".'
            else:
                assert host.file(file_to_check).contains(expected_config), \
                    f'Expected configuration was not found in "{file_to_check}"'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_yum_group_install(self, host):
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not applicable to Atomic host AMIs')

        with host.sudo():
            dev_tools_install_command = 'yum -y groupinstall "Development tools"'
            result = host.run(dev_tools_install_command)

            if result.failed:
                print(f'Command faild with error on first attempt: {result.stderr}')
                err_message = "This system is not registered to Red Hat Subscription Management"
                if err_message in result.stderr:
                    print('"Development tools" installation attempt failed. Trying to apply a workaround...')
                    host.run(
                        'echo -e "enabled=0" > /etc/yum/pluginconf.d/subscription-manager.conf'
                        ' && yum clean all'
                    )

                    assert host.run(dev_tools_install_command).succeeded, (
                        f'Error while installing Development tools '
                        f'group after two attempts with error: {result.stderr}'
                    )
            print('"Development tools" installed successfully.')

            package_to_check = 'glibc-devel'
            assert host.package(package_to_check).is_installed, \
                f'{package_to_check} is not installed'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_yum_package_install_kernel_debug(self, host):
        """
        BugZilla: 2117700
        Test that kernel-debug and kernel-debug-devel matching current kernel version are available in repo
        Open Question: which versions does this test apply? using all rhel versions for now
        """
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not applicable to Atomic host AMIs')

        print(f"kernel version: {host.check_output('uname -r')}")

        with host.sudo():
            assert host.run_test('yum -y install install kernel-debug-devel-$(uname -r)')
            assert host.run_test('yum -y install install kernel-debug-$(uname -r)')

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
    def test_pkg_signature_and_gpg_keys(self, host):
        """
        Check that "no pkg signature" is disabled
        Check that specified gpg keys are installed
        """
        with host.sudo():
            # print the gpg public keys installed
            print(host.check_output('rpm -qa | grep gpg-pubkey'))

            gpg_pubkey_base_cmd = "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'"

            # check no pkg signature is none
            assert 'none' not in host.check_output(gpg_pubkey_base_cmd + '| grep -v gpg-pubkey'), \
                'No pkg signature must be disabled'

            # check use only one keyid
            key_ids_command = ' '.join([gpg_pubkey_base_cmd,
                                        "| grep -vE '(gpg-pubkey|rhui)'",
                                        "| awk -F' ' '{print $NF}' | sort | uniq | wc -l"])
            assert int(host.check_output(key_ids_command)) == 1, \
                'Number of key IDs for rhui pkgs should be 1'

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

    @pytest.mark.run_on(['all'])
    def test_timezone_is_utc(self, host):
        """
        Check that the default timezone is set to UTC.
        BugZilla 1187669
        """
        assert 'UTC' in host.check_output('date'), 'Unexpected timezone. Expected to be UTC'

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


# TODO: Almost all these tests are cloud-agnostic
@pytest.mark.order(2)
@pytest.mark.usefixtures('rhel_sap_only')
class TestsAWSSAP:
    @pytest.mark.run_on(['rhel'])
    def test_sap_security_limits(self, host):
        """
        BugZilla 1959963
        JIRA RHELDST-10710
        """
        options = [
            '@sapsys hard nofile 1048576',
            '@sapsys soft nofile 1048576',
            '@dba hard nofile 1048576',
            '@dba soft nofile 1048576',
            '@sapsys hard nproc unlimited',
            '@sapsys soft nproc unlimited',
            '@dba hard nproc unlimited',
            '@dba soft nproc unlimited'
        ]

        with host.sudo():
            config_file = '/etc/security/limits.d/99-sap.conf'

            assert host.file(config_file).exists, \
                f'"{config_file}" is supposed to exist in SAP images'

            command_to_run = f"cat {config_file} | awk -F' ' '{{print($1,$2,$3,$4)}}'"

            content = host.check_output(command_to_run)

            for opt in options:
                assert opt in content, f'{opt} was expected in {config_file}'

    @pytest.mark.run_on(['rhel'])
    def test_sap_sysctl_files(self, host):
        """
        Check that sysctl config file(s) have the expected config
        BugZilla 1959962
        """
        cfg_files_to_check = [
            '/usr/lib/sysctl.d/sap.conf',
            '/etc/sysctl.d/sap.conf'
        ]

        expected_cfg_items = [
            'kernel.pid_max = 4194304',
            'vm.max_map_count = 2147483647'
        ]

        self.__check_sap_files_have_expected_config(host,
                                                    cfg_files_to_check,
                                                    expected_cfg_items,
                                                    'sysctl')

    @pytest.mark.run_on(['rhel'])
    def test_sap_tmp_files(self, host):
        """
        Check that temporary SAP config file(s) have the expected config
        BugZilla 1959979
        """
        cfg_files_to_check = [
            '/usr/lib/tmpfiles.d/sap.conf',
            '/etc/tmpfiles.d/sap.conf'
        ]

        expected_cfg_items = [
            re.escape('x /tmp/.sap*'),
            re.escape('x /tmp/.hdb*lock'),
            re.escape('x /tmp/.trex*lock')
        ]

        self.__check_sap_files_have_expected_config(host,
                                                    cfg_files_to_check,
                                                    expected_cfg_items,
                                                    'tmp')

    def __check_sap_files_have_expected_config(self,
                                               host,
                                               files_to_check,
                                               expected_config_items,
                                               files_type_name):
        with host.sudo():
            for cfg_file in files_to_check:
                missing_files_count = 0
                if host.file(cfg_file).exists:
                    for item in expected_config_items:
                        assert host.file(cfg_file).contains(item), \
                            f'"{item}" was expected in "{cfg_file}"'
                else:
                    missing_files_count += 1

        assert missing_files_count < len(files_to_check), \
            f'No SAP {files_type_name} files found'

    @pytest.mark.run_on(['rhel'])
    def test_sap_tuned(self, host):
        """
        Check that "sap-hana" is active in tuned-adm profile for SAP AMIs
        BugZilla 1959962
        """
        expected_cfg = 'sap-hana'

        with host.sudo():
            tuned_profile_cfg_file = '/etc/tuned/active_profile'
            assert host.file(tuned_profile_cfg_file).contains(expected_cfg), \
                f'"{expected_cfg}" is not set in "{tuned_profile_cfg_file}"'

            assert expected_cfg in host.check_output('tuned-adm active'), \
                'tuned-adm command returned unexpected active setting'

    # TODO: Only applicable to AWS
    @pytest.mark.run_on(['rhel'])
    def test_ha_specific_script(self, host, rhel_high_availability_only):
        # TODO: This script does not run correctly on RHEL-9.0 since awscli is not present in the repo.
        local_file_path = 'scripts/aws/rhel-ha-aws-check.sh'

        result = test_lib.run_local_script_in_host(host, local_file_path)

        assert result.rc == 0

    @pytest.mark.run_on(['rhel'])
    def test_sap_required_packages_are_installed(self, host):
        system_release = version.parse(host.system_info.release)

        required_pkgs = []

        required_pkgs.extend(['rhel-system-roles-sap'])

        # BugZilla 1959813
        required_pkgs.extend(['bind-utils', 'nfs-utils', 'tcsh'])

        # BugZilla 1959813
        required_pkgs.append('uuidd')

        # BugZilla 1959923, 1961168
        required_pkgs.extend(['cairo', 'expect', 'graphviz', 'gtk2',
                              'iptraf-ng', 'krb5-workstation', 'libaio'])

        # BugZilla 1959923, 1961168
        required_pkgs.extend(['libatomic', 'libcanberra-gtk2', 'libicu',
                              'libtool-ltdl', 'lm_sensors', 'net-tools'])

        required_pkgs.extend(['numactl', 'PackageKit-gtk3-module', 'xorg-x11-xauth', 'libnsl'])

        # BugZilla 1959962
        required_pkgs.append('tuned-profiles-sap-hana')

        # CLOUDX-557
        if system_release < version.parse('8.0'):
            required_pkgs.append('libpng12')

        # CLOUDX-367, CLOUDX-557
        if system_release >= version.parse('8.6'):
            required_pkgs.append('ansible-core')
        else:
            required_pkgs.append('ansible')

        # CLOUDX-557
        if system_release < version.parse('9.0'):
            required_pkgs.append('compat-sap-c++-9')

        missing_pkgs = [pkg for pkg in required_pkgs if not host.package(pkg).is_installed]

        assert len(missing_pkgs) == 0, f'Missing packages required by RHEL-SAP: {", ".join(missing_pkgs)}'


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
            f'rhui3-cds01.{region}.aws.ce.redhat.com',
            f'rhui3-cds02.{region}.aws.ce.redhat.com',
            f'rhui3-cds03.{region}.aws.ce.redhat.com',
            f'rhui2-cds01.{region}.aws.ce.redhat.com',
            f'rhui2-cds02.{region}.aws.ce.redhat.com',
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
