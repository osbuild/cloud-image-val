import json

import pytest
from packaging import version
import difflib

from lib import console_lib
from lib import test_lib


def get_offer_or_vm_name(instance_data_azure_web):
    """
    Helper function to get offer from Azure metadata, with VM name as fallback.
    Returns a tuple of (source_value, source_type) where source_type is 'Offer' or 'VM name'.
    """
    # Get offer from Azure metadata
    offer = instance_data_azure_web['compute']['storageProfile']['imageReference'].get('offer')

    if offer:
        return offer, 'Offer'

    # If offer is not found, use VM name as fallback
    vm_name = instance_data_azure_web['compute'].get('name')

    if vm_name:
        return vm_name, 'VM name'

    return None, None


def get_expected_rhui_rpm_name(host, source_string):
    """
    Helper function to determine the expected RHUI client package name
    based on the system release and Azure VM offer name or VM name.
    """
    system_release = version.parse(host.system_info.release)

    # Check for last minor release versions (e.g., RHEL 8.10 or 9.10)
    is_base_version = system_release.minor == 10

    # Start with the basic name structure
    expected_rhui_name = f'rhui-azure-rhel{system_release.major}'

    if source_string:
        # Add source-specific suffixes
        source_lower = source_string.lower()

        # Dictionary mapping keywords in the source string to the expected RHUI suffix
        source_suffixes = {
            'sap-ha': '-sap-ha',
            'sapapps': '-sapapps',
            'arm64': '-arm64',
        }

        # Iterate through the dictionary and check if any key is in the source string.
        # Add the first matching suffix found.
        for keyword, suffix in source_suffixes.items():
            if keyword in source_lower:
                # Add '-base' suffix if applicable
                if is_base_version:
                    expected_rhui_name += '-base'
                expected_rhui_name += suffix
                break

    return expected_rhui_name


def get_expected_rhui_cert_name(host, source_string):
    """
    Determine the expected RHUI certificate name based on RHUI rpm name.
    Certificate names follow the same pattern as RPM names but with 'content' prefix.
    """
    rhui_rpm_name = get_expected_rhui_rpm_name(host, source_string)
    system_release = version.parse(host.system_info.release)

    # Remove the 'rhui-azure-rhel{version}' part and replace with 'content'
    rhui_prefix = f'rhui-azure-rhel{system_release.major}'

    # Vanilla RHEL x86 cert name
    cert_name = 'content.crt'

    if rhui_rpm_name.startswith(rhui_prefix):
        suffix = rhui_rpm_name[len(rhui_prefix):]  # Get everything after the prefix
        if suffix:
            cert_name = f'content{suffix}.crt'
        elif system_release.minor == 10 or test_lib.is_rhel_cvm:
            cert_name = 'content-base.crt'

    return cert_name


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
    @pytest.mark.usefixtures('rhel_cvm_skip')
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
    @pytest.mark.usefixtures('rhel_cvm_skip')
    def test_osdisk_size(self, host):
        """
        Verify os disk size is 63G/62.9G
        """
        expected_disk_size = '63G'

        # CLOUDX-764
        if version.parse(host.system_info.release) >= version.parse('9.3'):
            expected_disk_size = '62.5G'

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
    def test_waagent_resourcedisk_format(self, host):
        """
        Verify the ResourceDisk.Format is disabled in waagent.conf
        """
        with host.sudo():
            assert host.file('/etc/waagent.conf').contains('ResourceDisk.Format=n'), \
                'ResourceDisk.Format=n has to be present in /etc/waagent.conf'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_rhui_client_rpm_matches_offer(self, host, instance_data_azure_web):
        """
        Verify that exactly one RHUI client rpm is installed and that it matches
        the VM's Offer value or VM name (fallback).
        """
        # Get offer from Azure metadata with fallback to VM name
        source_value, source_type = get_offer_or_vm_name(instance_data_azure_web)

        # Ensure we have either offer or vm_name
        assert source_value, 'Neither Offer nor VM name is present in Azure metadata. Test cannot proceed.'

        print(f'Azure VM {source_type}: {source_value}')

        # Determine expected RHUI package name using the helper function
        expected_rhui_name = get_expected_rhui_rpm_name(host, source_value)

        print(f'Expected RHUI client package name: {expected_rhui_name}')

        # Get all installed RHUI client packages
        rhui_packages_cmd = host.run('rpm -qa | grep "^rhui-azure-rhel"')

        print(f'rhui_packages_cmd.stdout: {rhui_packages_cmd.stdout}')
        rhui_cmd = host.run('rpm -qa | grep "^rhui"')
        print(f'rhui_cmd.stdout: {rhui_cmd.stdout}')

        # Check if the command ran successfully (exit code 0)
        assert rhui_packages_cmd.rc == 0, 'Failed to get RHUI client packages'

        rhui_packages = rhui_packages_cmd.stdout.strip().split('\n')

        # Filter out empty strings
        rhui_packages = [pkg for pkg in rhui_packages if pkg]

        print(f'Found RHUI client packages: {rhui_packages}')

        assert len(rhui_packages) == 1, \
            f'Expected exactly one RHUI client rpm, but found {len(rhui_packages)}: {rhui_packages}'

        installed_package = rhui_packages[0]

        # Check if the installed package name starts with expected name
        assert installed_package.startswith(expected_rhui_name), \
            f'RHUI client package "{installed_package}" does not match \
            expected name "{expected_rhui_name}" for {source_type.lower()} "{source_value}"'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_rhui_certificate_date(self, host, instance_data_azure_web):
        """
        Verify /etc/pki/rhui/product/content{*}.crt exists.
        The certificate name matches the RHUI rpm name pattern.
        Check end time of the certificate to see if it expires within 10 weeks.
        """
        # Get offer from Azure metadata with fallback to VM name
        source_value, source_type = get_offer_or_vm_name(instance_data_azure_web)

        # Ensure we have either offer or vm_name
        assert source_value, 'Neither Offer nor VM name is present in Azure metadata. Test cannot proceed.'

        print(f'Azure VM {source_type}: {source_value}')

        # Determine expected certificate name using the helper function
        expected_cert_name = get_expected_rhui_cert_name(host, source_value)
        cert_file = f'/etc/pki/rhui/product/{expected_cert_name}'

        print(f'Expected RHUI certificate: {cert_file}')

        with host.sudo():
            # Check if the expected certificate file exists
            cert_found = host.file(cert_file).exists

            assert cert_found, f'The RHUI certificate "{cert_file}" was not found.'

            # Check if certificate is valid for at least 10 weeks from now
            # 10 weeks = 10 * 7 * 24 * 60 * 60 = 6,048,000 seconds
            ten_weeks_seconds = 10 * 7 * 24 * 60 * 60

            result = host.run(f'openssl x509 -noout -in {cert_file} -enddate -checkend {ten_weeks_seconds}')

            assert result.succeeded, \
                'The certificate will expire within 10 weeks.' \
                'It should be valid for at least 10 weeks from now.'

    @pytest.mark.run_on(['rhel'])
    def test_redhat_cloud_client_packages_config(self, host, instance_data_azure_web):
        """
        If offer/vm_name contains 'byos', then:
        1. redhat-cloud-client-configuration must be installed
        2. redhat-cloud-client-configuration-cdn must NOT be installed
        CLOUDX-1533
        """
        # Get offer from Azure metadata with fallback to VM name
        source_value, source_type = get_offer_or_vm_name(instance_data_azure_web)

        # Check if it's a BYOS image (case-insensitive)
        if not source_value or 'byos' not in source_value.lower():
            pytest.skip(f"Test skipped: {source_type} '{source_value}' does not contain 'byos'.")

        pkg_rhccc_generic = 'redhat-cloud-client-configuration'
        pkg_rhccc_cdn = 'redhat-cloud-client-configuration-cdn'

        assert host.package(pkg_rhccc_generic).is_installed, \
            f"BYOS system must have '{pkg_rhccc_generic}' installed."

        assert not host.package(pkg_rhccc_cdn).is_installed, \
            f"BYOS system must NOT have '{pkg_rhccc_cdn}' installed."

    @pytest.mark.run_on(['rhel'])
    def test_boot_efi_size_on_cvm(self, host):
        """
        Verify the existence and size of the /boot/efi partition.
        The expected minimum size is 512 MiB.
        """
        if not test_lib.is_rhel_cvm(host):
            pytest.skip("Not applicable to the VM RHEL flavor.")

        assert host.mount_point("/boot/efi").exists, "/boot/efi mount is missing"

        result = host.run("df --block-size=1 /boot/efi | tail -1")
        parts = result.stdout.split()
        total_bytes = int(parts[1])
        min_size_mib = 510
        required_size = min_size_mib * 1024 * 1024
        assert total_bytes >= required_size, \
            f'/boot/efi partition is too small: {total_bytes} bytes. Required: {min_size_mib} MiB)'
