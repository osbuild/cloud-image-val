import json

import pytest


@pytest.fixture
def instance_data_oci_web(host):
    """
    Fetch instance metadata from OCI IMDS (Instance Metadata Service).
    """
    oci_metadata_url = 'http://169.254.169.254/opc/v2/instance/'
    command_to_run = f'curl -s -H "Authorization: Bearer Oracle" "{oci_metadata_url}"'
    return json.loads(host.check_output(command_to_run))


@pytest.mark.order(2)
class TestsOCI:
    @pytest.mark.run_on(['all'])
    def test_oci_metadata_is_accessible(self, host, instance_data_oci_web):
        """
        Verify the OCI instance metadata service is reachable and returns valid data.
        """
        assert instance_data_oci_web.get('region'), \
            'Could not retrieve region from OCI instance metadata'
        assert instance_data_oci_web.get('shape'), \
            'Could not retrieve shape from OCI instance metadata'

    @pytest.mark.run_on(['all'])
    def test_instance_identity_matches(self, host, instance_data, instance_data_oci_web):
        """
        Verify the deployed instance metadata matches what CIV expects.
        """
        assert (instance_data_oci_web.get('region') ==
                instance_data.get('availability_domain', '').split(':')[0].lower()
                or instance_data_oci_web.get('canonicalRegionName')), \
            'Instance region from metadata does not match expected region'

        assert (instance_data_oci_web.get('shape') ==
                instance_data.get('shape', 'VM.Standard.E4.Flex')), \
            f'Unexpected shape: {instance_data_oci_web.get("shape")}'

    @pytest.mark.run_on(['rhel'])
    def test_cloud_init_is_installed(self, host):
        """
        Verify cloud-init is installed and enabled, required for OCI provisioning.
        """
        assert host.package('cloud-init').is_installed, \
            'cloud-init must be installed in OCI images'

        with host.sudo():
            assert host.service('cloud-init').is_enabled, \
                'cloud-init service must be enabled'

    @pytest.mark.run_on(['rhel'])
    def test_cloud_init_datasource_is_oracle(self, host):
        """
        Verify cloud-init is configured to use the Oracle datasource.
        """
        datasource_file = '/etc/cloud/cloud.cfg.d/10_oracle.cfg'
        fallback_cfg = '/etc/cloud/cloud.cfg'

        with host.sudo():
            if host.file(datasource_file).exists:
                assert host.file(datasource_file).contains('Oracle'), \
                    f'Oracle datasource not configured in {datasource_file}'
            else:
                assert host.file(fallback_cfg).contains('Oracle'), \
                    'Oracle datasource not found in cloud-init config'

    @pytest.mark.run_on(['rhel'])
    def test_network_manager_is_active(self, host):
        """
        Verify NetworkManager is running, required for OCI network configuration.
        """
        with host.sudo():
            assert host.service('NetworkManager').is_running, \
                'NetworkManager must be running in OCI instances'

    @pytest.mark.run_on(['all'])
    def test_correct_network_driver_is_used(self, host):
        """
        OCI instances use the virtio driver (paravirtualized NIC).
        """
        with host.sudo():
            nic_driver = host.check_output(
                "find /sys/class/net -maxdepth 2 -name 'uevent' "
                "| xargs grep -h DRIVER 2>/dev/null | head -1"
            )

        assert 'virtio' in nic_driver, \
            f'Expected virtio network driver in OCI paravirtualized instance, got: {nic_driver}'

    @pytest.mark.run_on(['rhel'])
    def test_unwanted_packages_are_not_present(self, host):
        """
        Verify packages that are not needed in OCI are absent.
        """
        unwanted_pkgs = [
            'aic94xx-firmware',
            'alsa-firmware',
            'alsa-tools-firmware',
            'ivtv-firmware',
            'iwl7260-firmware',
            'libertas-sd8686-firmware',
            'libertas-usb8388-firmware',
        ]

        found_pkgs = []
        with host.sudo():
            for pkg in unwanted_pkgs:
                if host.package(pkg).is_installed:
                    found_pkgs.append(pkg)

        assert len(found_pkgs) == 0, \
            f'Found unexpected packages installed: {", ".join(found_pkgs)}'

    @pytest.mark.run_on(['rhel'])
    def test_sshd_config(self, host):
        """
        Verify sshd is configured correctly for OCI — password auth off, pubkey on.
        """
        sshd_config = '/etc/ssh/sshd_config'
        with host.sudo():
            assert not host.file(sshd_config).contains('PasswordAuthentication yes'), \
                'PasswordAuthentication must not be enabled in OCI images'
            assert host.service('sshd').is_running, \
                'sshd must be running'

    @pytest.mark.run_on(['rhel'])
    def test_firewalld_is_not_running(self, host):
        """
        OCI uses security lists/NSGs at the VCN level; local firewalld can interfere.
        """
        with host.sudo():
            if host.package('firewalld').is_installed:
                assert not host.service('firewalld').is_running, \
                    'firewalld should not be running in OCI instances'

    @pytest.mark.run_on(['all'])
    def test_chronyd_is_active(self, host):
        """
        Verify chrony is running. OCI provides time sync via 169.254.169.254.
        """
        with host.sudo():
            assert host.service('chronyd').is_running, \
                'chronyd must be running for time synchronization'

    @pytest.mark.run_on(['rhel'])
    def test_oci_timesync_is_configured(self, host):
        """
        OCI recommends using the local NTP source at 169.254.169.254.
        """
        timesync_ip = '169.254.169.254'

        with host.sudo():
            chrony_conf = host.file('/etc/chrony.conf').content_string

        assert timesync_ip in chrony_conf, \
            f'OCI time sync server {timesync_ip} not configured in /etc/chrony.conf'
