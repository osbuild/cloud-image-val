import json

import pytest
from packaging import version
import difflib

from lib import console_lib
from lib import test_lib


@pytest.fixture
def instance_data_azure_web(host):  # pylint: disable=bad-indentation
    azure_metadata_url = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
    command_to_run = f'curl -s -H Metadata:true --noproxy "*" "{azure_metadata_url}"'
    return json.loads(host.check_output(command_to_run))


@pytest.mark.order(2)
class TestsAzure:
    @pytest.mark.run_on(['rhel'])
    def test_68_azure_sriov_nm_unmanaged_rules_file_content(self, host):
        """
        Check file /etc/udev/rules.d/68-azure-sriov-nm-unmanaged.rules
        """
        system_release = version.parse(host.system_info.release)
        local_file = 'data/azure/68-azure-sriov-nm-unmanaged.rules'
        remote_file = '/etc/udev/rules.d/68-azure-sriov-nm-unmanaged.rules'

        if system_release.major == 8:
            assert test_lib.compare_local_and_remote_file(host, local_file, remote_file), \
                f'{remote_file} has unexpected content'

        '''
        # ToDO: uncomment this block when fixed in compose
        # RHEL-100574
        if system_release >= version.parse('9.7') or system_release >= version.parse('10.1'):
            assert not host.file(remote_file).exists, \
                f"The file '{remote_file}' should not exist on RHEL '{system_release}'"
        '''

    @pytest.mark.run_on(['rhel'])
    def test_91_azure_datasource_file_content(self, host):
        """
        Check file /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg
        """
        local_file = 'data/azure/91-azure_datasource.cfg'
        remote_file = '/etc/cloud/cloud.cfg.d/91-azure_datasource.cfg'

        assert test_lib.compare_local_and_remote_file(host, local_file, remote_file), \
            f'{remote_file} has unexpected content'

    @pytest.mark.run_on(['rhel'])
    def test_authconfig_file(self, host):
        """
        Verify no /etc/sysconfig/authconfig file in RHEL8 and later
        """
        file_to_check = '/etc/sysconfig/authconfig'

        assert not host.file(file_to_check).exists, \
            f'{file_to_check} should not exist in RHEL 8 and later'

    @pytest.mark.run_on(['all'])
    @pytest.mark.exclude_on(['fedora'])
    def test_sshd_config_client_alive_interval(self, host):
        """
        Verify ClientAliveInterval 180 in /etc/ssh/sshd_config
        """
        sshd_config_file = '/etc/ssh/sshd_config'
        with host.sudo():
            assert host.file(sshd_config_file).contains('ClientAliveInterval 180'), \
                f'ClientAliveInterval not set correctly in {sshd_config_file}'

    # @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_grub_params(self, host):
        """
        Verify /etc/default/grub params excluding GRUB_CMDLINE_LINUX line,
        which is tested in test_cmdline_console
        """
        release_version = version.parse(host.system_info.release)
        architecture = host.system_info.arch
        remote_file_path = '/etc/default/grub'

        # 1. Determine local expected file based on version
        if release_version >= version.parse('9.6'):
            local_file = 'data/azure/grub_rhel9.6+'
        elif release_version >= version.parse('9.3'):
            local_file = 'data/azure/grub_rhel9.3+'
        else:
            local_file = f'data/azure/grub_rhel{release_version.major}'

        # 2. Get and filter content from both sources
        try:
            remote_grub_lines = test_lib.get_filtered_grub_content_lines(host, remote_file_path)
        except OSError as e:
            pytest.fail(f"Could not read remote file {remote_file_path}: {e}")

        try:
            expected_grub_lines = test_lib.get_filtered_grub_content_lines(None, local_file)
        except OSError as e:
            pytest.fail(f"Could not read local file: {local_file}: {e}")

        # 3. Apply architecture-specific changes to the expected content
        if release_version >= version.parse('9.6'):
            expected_grub_lines = test_lib.apply_architecture_specific_grub_terminal(
                expected_grub_lines, architecture
            )

        # 4. Compare the two lists of lines and generate a meaningful diff report
        diff = list(difflib.unified_diff(
            expected_grub_lines,
            remote_grub_lines,
            fromfile=f'Expected ({local_file})',
            tofile=f'Actual ({remote_file_path})',
            lineterm=''
        ))

        # The assert statement checks if the diff list is empty. If it's not, there are differences.
        assert not diff, \
            f'{remote_file_path} has unexpected content (excluding GRUB_CMDLINE_LINUX).\n' \
            f'Differences found:\n' \
            + '\n'.join(diff)

    @pytest.mark.run_on(['rhel'])
    def test_hyperv_drivers(self, host):
        """
        Verify hyperv drivers are loaded
        """
        hyperv_driver_list = [
            'hv_utils',
            'hv_balloon',
            'hv_storvsc',
            'scsi_transport_fc',
            'hid_hyperv',
            'hv_netvsc',
            'hyperv_keyboard',
            'hv_vmbus'
        ]

        if version.parse(host.system_info.release) < version.parse('9.0'):
            hyperv_driver_list.append('hyperv_fb')
        else:
            hyperv_driver_list.append('hyperv_drm')

        with host.sudo():
            output = host.check_output('lsmod | grep -iE "hv|hyperv"')

            for drv in hyperv_driver_list:
                assert drv in output, f'{drv} driver is not loaded'

    @pytest.mark.run_on(['all'])
    def test_metadata(self, host, instance_data_azure_web):
        assert instance_data_azure_web.get('compute').get('osType') == 'Linux', \
            'Cannot parse metadata to get azEnvironment'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_image_generation(self, host, instance_data_azure_web):
        """
        (image test only) Check generation according to image name
        """
        sku = instance_data_azure_web['compute']['storageProfile']['imageReference']['sku']

        if not sku:
            pytest.skip('SKU is not present in image metadata. This test will be skipped.')

        with host.sudo():
            is_efi = host.run('dmesg | grep -w EFI').exit_status == 0

        if not is_efi:
            assert sku.endswith('gen1'), 'SKU does not match with image generation type'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_osdisk_size(self, host):
        """
        Verify os disk size is 63G/62.9G
        """
        expected_disk_size = '63G'

        # CLOUDX-764
        if version.parse(host.system_info.release) >= version.parse('9.3'):
            expected_disk_size = '62.9G'

        with host.sudo():
            base_command = 'fdisk -l | grep "Linux LVM"'

            if version.parse(host.system_info.release) < version.parse('8.0'):
                cmd = f'{base_command} | awk "{{print $4}}"'
            else:
                cmd = f'{base_command} | awk "{{print $5}}"'

            assert expected_disk_size in host.check_output(cmd), 'Unexpected Linux LVM disk size'

    @pytest.mark.run_on(['all'])
    def test_pwquality_conf(self, host):
        """
        Check file /etc/security/pwquality.conf
        """
        file_to_check = '/etc/security/pwquality.conf'
        expected_settings = [
            'dcredit = 0',
            'lcredit = 0',
            'minclass = 3',
            'minlen = 6',
            'ocredit = 0',
            'ucredit = 0',
        ]

        if host.system_info.distribution == 'fedora':
            expected_settings[2] = 'minclass = 0'
            expected_settings[3] = 'minlen = 8'

        with host.sudo():
            debug = {'libpwquality version': host.package('libpwquality').version,
                     'pwquality.conf file content': host.file(file_to_check).content_string}
            for setting in expected_settings:
                assert host.file(file_to_check).contains(f'{setting}'), \
                    f'Expected setting "{setting}" not found in "{file_to_check}"'

        print(console_lib.print_debug(debug))

    @pytest.mark.run_on(['all'])
    @pytest.mark.exclude_on(['fedora'])
    def test_services_running(self, host):
        """
        Verify the necessary services are running
        """
        service_list = [
            'waagent', 'cloud-init-local', 'cloud-init',
            'cloud-config', 'cloud-final', 'hypervkvpd', 'sshd'
        ]

        with host.sudo():
            for service in service_list:
                assert host.service(service).is_running

    @pytest.mark.run_on(['rhel'])
    def test_pkg_wanted(self, host):
        """
        Check that the expected packages are installed.
        """
        wanted_pkgs = [
            'yum-utils', 'redhat-release-eula', 'cloud-init', 'insights-client',
            'tar', 'rsync', 'NetworkManager', 'cloud-utils-growpart', 'gdisk',
            'grub2-tools', 'WALinuxAgent', 'firewalld', 'chrony',
            'hypervkvpd', 'hyperv-daemons-license', 'hypervfcopyd', 'hypervvssd', 'hyperv-daemons'
        ]

        # RHELMISC-6651 gdisk retired in RHEL10
        # CLOUDX-1335 hypervfcopyd retired in RHEL10 aarch64
        system_release = version.parse(host.system_info.release)
        if system_release.major >= 10:
            wanted_pkgs.remove('gdisk')

            if host.system_info.arch == 'aarch64':
                wanted_pkgs.remove('hypervfcopyd')

        missing_pkgs = [pkg for pkg in wanted_pkgs if not host.package(pkg).is_installed]

        assert len(missing_pkgs) == 0, f'One or more packages are missing: {", ".join(missing_pkgs)}'

    @pytest.mark.run_on(['all'])
    @pytest.mark.exclude_on(['fedora'])
    def test_waagent_resourcedisk_format(self, host):
        """
        Verify the ResourceDisk.Format is disabled in waagent.conf
        """
        with host.sudo():
            assert host.file('/etc/waagent.conf').contains('ResourceDisk.Format=n'), \
                'ResourceDisk.Format=n has to be present in /etc/waagent.conf'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_rhui_certificate_date(self, host):
        """
        Verify /etc/pki/rhui/product/content{*}.crt exists.
        Starting from RHEL 8.8 & 9.2, the certificate file was renamed to content-base.crt.
        Check end time of the certificate to see if it has expired
        """
        with host.sudo():
            rhui_package = host.run('rpm -qa | grep rhui').stdout

            print(f'Rpm package found: {rhui_package}')
            test_lib.print_host_command_output(host, f'rpm -ql {rhui_package}')
            test_lib.print_host_command_output(host, 'yum -v repolist')

            cert_file = ''
            cert_found = False

            if test_lib.is_rhel_saphaus(host):
                cert_file = '/etc/pki/rhui/product/content-sap-ha.crt'
                cert_found = host.file(cert_file).exists
            else:
                possible_cert_files = [
                    '/etc/pki/rhui/product/content.crt',
                    '/etc/pki/rhui/product/content-base.crt'
                ]

                for cert in possible_cert_files:
                    if host.file(cert).exists:
                        cert_file = cert
                        cert_found = True
                        break

            assert cert_found, 'The RHUI certificate was not found.'

            test_lib.print_host_command_output(host, f'ls -l {cert_file} 2>&1')

            result = host.run(f'openssl x509 -noout -in {cert_file} -enddate -checkend 0')

            print(result.stdout)

            assert result.succeeded, \
                'The certificate appears to have expired. Check the test case output for more details.'

    @pytest.mark.run_on(['rhel'])
    def test_cmdline_console(self, host):
        """
        Verify that console=ttyS0 earlyprintk=ttyS0 rootdelay=300 are in cmdline
        """
        file_to_check = '/proc/cmdline'

        expected_config = [
            'console=ttyS0',
            'earlyprintk=ttyS0',
            'rootdelay=300'
        ]

        if host.system_info.arch == 'aarch64':
            expected_config = ['console=ttyAMA0']

        if version.parse(host.system_info.release) >= version.parse('9.6'):
            expected_config.append('nvme_core.io_timeout=240')

        with host.sudo():
            for item in expected_config:
                assert host.file(file_to_check).contains(item), \
                    f'{item} was expected in {file_to_check}'
