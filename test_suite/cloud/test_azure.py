import json
import pytest

from lib import test_lib


@pytest.fixture
def instance_data_azure_web(host):
    azure_metadata_url = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
    command_to_run = f'curl -s -H Metadata:true --noproxy "*" "{azure_metadata_url}"'
    return json.loads(host.check_output(command_to_run))


@pytest.mark.order(2)
class TestsAzure:
    @pytest.mark.run_on(['rhel7.9'])
    def test_66_azure_storage_rules_file_content(self, host):
        """
        Check file /etc/udev/rules.d/66-azure-storage.rules
        """
        local_file = 'data/azure/66-azure-storage.rules'
        remote_file = '/etc/udev/rules.d/66-azure-storage.rules'

        assert test_lib.compare_local_and_remote_file(host, local_file, remote_file), \
            f'{remote_file} has unexpected content'

    @pytest.mark.run_on(['rhel8.6', 'rhel9.0'])
    def test_68_azure_sriov_nm_unmanaged_rules_file_content(self, host):
        """
        Check file /etc/udev/rules.d/68-azure-sriov-nm-unmanaged.rules
        """
        local_file = 'data/azure/68-azure-sriov-nm-unmanaged.rules'
        remote_file = '/etc/udev/rules.d/68-azure-sriov-nm-unmanaged.rules'

        assert test_lib.compare_local_and_remote_file(host, local_file, remote_file), \
            f'{remote_file} has unexpected content'

    @pytest.mark.run_on(['rhel8.5', 'rhel8.6', 'rhel9.0'])
    def test_91_azure_datasource_file_content(self, host):
        """
        Check file /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg
        """
        local_file = 'data/azure/91-azure_datasource.cfg'
        remote_file = '/etc/cloud/cloud.cfg.d/91-azure_datasource.cfg'

        assert test_lib.compare_local_and_remote_file(host, local_file, remote_file), \
            f'{remote_file} has unexpected content'

    @pytest.mark.run_on(['rhel7.9'])
    def test_99_azure_product_uuid_rules_file_content(self, host):
        """
        Check file /etc/udev/rules.d/99-azure-product-uuid.rules
        """
        local_file = 'data/azure/99-azure-product-uuid.rules'
        remote_file = '/etc/udev/rules.d/99-azure-product-uuid.rules'

        assert test_lib.compare_local_and_remote_file(host, local_file, remote_file), \
            f'{remote_file} has unexpected content'

    @pytest.mark.run_on(['rhel'])
    def test_authconfig_file(self, host):
        """
        Verify no /etc/sysconfig/authconfig file, or if it has correct content in RHEL 7.x
        """
        file_to_check = '/etc/sysconfig/authconfig'

        with host.sudo():
            if float(host.system_info.release) < 8.0:
                # In RHEL-7, check authconfig content
                local_file = 'data/azure/authconfig'

                assert test_lib.compare_local_and_remote_file(host, local_file, file_to_check), \
                    f'{file_to_check} has unexpected content'
            else:
                # In RHEL-8 authconfig file should not exist
                assert not host.file(file_to_check).exists, \
                    f'{file_to_check} should not exist in RHEL 8 and later'

    @pytest.mark.run_on(['rhel'])
    def test_blacklist(self, host):
        """
        BugZilla 1645772
        nouveau,lbm-nouveau,floppy,skx_edac,intel_cstate should be disabled
        """
        file_pattern = '/lib/modprobe.d/blacklist-*.conf'

        blacklist = ['nouveau', 'lbm-nouveau', 'floppy', 'amdgpu']

        if float(host.system_info.release) < 9.0:
            blacklist.extend(['skx_edac', 'intel_cstate'])

        with host.sudo():
            assert host.run('lsmod | grep nouveau').exit_status != 0, \
                'nouveau kernel module should not be loaded'

            files_content = host.check_output(f'cat {file_pattern}')

            print(files_content)

            for item in blacklist:
                assert item in files_content, f'{item} is not blacklisted'

    @pytest.mark.run_on(['all'])
    def test_sshd_config_client_alive_interval(self, host):
        """
        Verify ClientAliveInterval 180 in /etc/ssh/sshd_config
        """
        sshd_config_file = '/etc/ssh/sshd_config'
        with host.sudo():
            assert host.file(sshd_config_file).contains('ClientAliveInterval 180'), \
                f'ClientAliveInterval not set correctly in {sshd_config_file}'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_grub_params(self, host):
        """
        Verify /etc/default/grub params
        """
        grub_files_by_rhel_major_version = {
            7: 'grub_rhel7',
            8: 'grub_rhel8',
            9: 'grub_rhel9'
        }

        rhel_major_version = int(float(host.system_info.release))

        local_file = 'data/azure/{}'.format(grub_files_by_rhel_major_version[rhel_major_version])
        remote_file = '/etc/default/grub'

        assert test_lib.compare_local_and_remote_file(host, local_file, remote_file), \
            f'{remote_file} has unexpected content'

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

        if float(host.system_info.release) < 9.0:
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

        with host.sudo():
            is_efi = host.run('dmesg | grep -w EFI').exit_status == 0

        if not is_efi:
            assert sku.endswith('gen1'), 'SKU does not match with image generation type'

    @pytest.mark.run_on(['rhel'])
    def test_osdisk_size(self, host):
        """
        Verify os disk size is 64 GiB
        """
        with host.sudo():
            base_command = 'fdisk -l | grep "Linux LVM"'

            if float(host.system_info.release) < 8.0:
                cmd = f'{base_command} | awk "{{print $4}}"'
            else:
                cmd = f'{base_command} | awk "{{print $5}}"'

            assert '63G' in host.check_output(cmd), 'Unexpected Linux LVM disk size'

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

        with host.sudo():
            for setting in expected_settings:
                assert host.file(file_to_check).contains(f'^{setting}'), \
                    f'Expected setting "{setting}" not found in "{file_to_check}"'

    @pytest.mark.run_on(['all'])
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
            'yum-utils', 'redhat-release-eula', 'cloud-init',
            'tar', 'rsync', 'NetworkManager', 'cloud-utils-growpart', 'gdisk',
            'grub2-tools', 'WALinuxAgent', 'firewalld', 'chrony',
            'hypervkvpd', 'hyperv-daemons-license', 'hypervfcopyd', 'hypervvssd', 'hyperv-daemons'
        ]

        product_version = float(host.system_info.release)
        if product_version < 8.0:
            wanted_pkgs.append('dhclient')
        else:
            wanted_pkgs.extend(['insights-client', 'dhcp-client'])

        missing_pkgs = [pkg for pkg in wanted_pkgs if not host.package(pkg).is_installed]

        assert len(missing_pkgs) == 0, f'One or more packages are missing: {", ".join(missing_pkgs)}'

    @pytest.mark.run_on(['all'])
    def test_waagent_resourcedisk_format(self, host):
        """
        Verify the ResourceDisk.Format is disabled in waagent.conf
        """
        with host.sudo():
            assert host.file('/etc/waagent.conf').contains('ResourceDisk.Format=n'), \
                'ResourceDisk.Format=n has to be present in /etc/waagent.conf'
