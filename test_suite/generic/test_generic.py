import pytest
from lib import test_lib


class TestsGeneric:
    @pytest.mark.run_on(['all'])
    def test_bash_history_is_empty(self, host):
        users = [host.user().name, 'root']

        for u in users:
            file_path = f'/home/{u}/.bash_history'
            bash_history_file = host.file(file_path)
            if bash_history_file.exists:
                file_content_length = len(bash_history_file.content_string)
                assert file_content_length == 0, f'{file_path} must be empty or nonexistent'

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
        product_release_version = float(host.system_info.release)

        if product_release_version < 9.0:
            expected_content = ['crashkernel=auto']
        elif host.system_info.arch == 'x86_64':
            expected_content = ['crashkernel=1G-4G:192M', '4G-64G:256M', '64G-:512M']
        else:
            expected_content = ['crashkernel=2G-:448M']

        with host.sudo(host.user().name):
            for item in expected_content:
                assert host.file('/proc/cmdline').contains(item), \
                    'crashkernel must be enabled'

    @pytest.mark.run_on(['all'])
    def test_cpu_flags_are_correct(self, host):
        """
        Check various CPU flags.
        BugZilla 1061348
        """
        arch = 'x86_64'
        if host.system_info.arch == arch:
            pytest.skip(f'Not applicable to {arch}')

        expected_flags = [
            'avx',
            'xsave',
        ]

        # TODO We may have a false positive here. The above flags are not applicable to ARM as per the thread below:
        # https://unix.stackexchange.com/questions/43539/what-do-the-flags-in-proc-cpuinfo-mean
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

    @pytest.mark.run_on(['all'])
    def test_no_avc_denials(self, host):
        """
        Check there is no avc denials (selinux).
        """
        with host.sudo():
            assert 'no matches' in host.check_output('x=$(ausearch -m avc 2>&1 &); echo $x'), \
                'There should not be any avc denials (selinux)'

    @pytest.mark.run_on(['rhel'])
    def test_cert_product_version_is_correct(self, host):
        """
        BugZilla 1938930
        Issue RHELPLAN-60817
        """
        product_version = float(host.system_info.release)

        if product_version < 8.0:
            rpm_to_check = 'redhat-release-server'
        else:
            rpm_to_check = 'redhat-release'

        with host.sudo():
            host.run_test(f'rpm -q {rpm_to_check}')

            cert_version = host.check_output('rct cat-cert /etc/pki/product-default/*.pem | grep Version')

            assert f'Version: {product_version}' in cert_version, \
                'Inconsistent version in pki certificate'

    @pytest.mark.run_on(['all'])
    def test_inittab_and_systemd(self, host):
        """
        Check default runlevel or systemd target.
        """
        kernel_release = host.check_output('uname -r')

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

        product_version = float(host.system_info.release)

        release_file = 'redhat-release'
        if host.system_info.distribution == 'fedora':
            release_file = 'fedora-release'

        with host.sudo():
            command_to_run = "rpm -q --qf '%{VERSION}' --whatprovides " + release_file
            package_release_version = float(host.check_output(command_to_run))

        assert product_version == package_release_version, \
            f'product version ({product_version}) does not match package release version'

    @pytest.mark.pub
    @pytest.mark.run_on(['all'])
    def test_release_version_in_image_name(self, host, instance_data):
        """
        Check if release version is on the image name
        """
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not run in atomic images')

        cloud_image_name = instance_data['name']
        product_version = float(host.system_info.release)

        assert str(product_version).replace('.', '-') in cloud_image_name, 'product version is not in image name'

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

    @pytest.mark.run_on(['all'])
    def test_timezone_is_utc(self, host):
        """
        Check that the default timezone is set to UTC.
        BugZilla 1187669
        """
        assert 'UTC' in host.check_output('date'), 'Unexpected timezone. Expected to be UTC'

    @pytest.mark.pub
    @pytest.mark.run_on(['all'])
    def test_pkg_signature_and_gpg_keys(self, host):
        """
        Check that "no pkg signature" is disabled
        Check that specified gpg keys are installed
        """
        if host.system_info.distribution == 'fedora':
            num_of_gpg_keys = 1
        else:
            num_of_gpg_keys = 2

        with host.sudo():
            gpg_pubkey_cmd = "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n' | grep -v gpg-pubkey"
            gpg_pubkey_content = host.check_output(gpg_pubkey_cmd)

            assert 'none' not in gpg_pubkey_content, 'No pkg signature must be disabled'

            num_of_key_ids = host.check_output(gpg_pubkey_cmd + " | awk -F' ' '{print $NF}'|sort|uniq|wc -l")
            assert int(num_of_key_ids) == 1, 'Number of key IDs should be 1'

            assert int(host.check_output('rpm -q gpg-pubkey|wc -l')) == num_of_gpg_keys, \
                f'There should be {num_of_gpg_keys} gpg key(s) installed'

    @pytest.mark.run_on(['rhel'])
    def test_grub_config(self, host):
        grub2_file = '/boot/grub2/grubenv'
        linked_to = grub2_file

        with host.sudo():
            if host.file('/sys/firmware/efi').exists:
                if float(host.system_info.release) < 8.0:
                    linked_to = '/boot/efi/EFI/redhat/grubenv'

            assert host.file(grub2_file).linked_to == linked_to


class TestsServices:
    @pytest.mark.run_on(['all'])
    def test_sshd(self, host):
        with host.sudo():
            sshd = host.service('sshd')
            assert sshd.is_running, 'ssh.service is not active'

            pass_auth_config_name = 'PasswordAuthentication'

            assert host.file('/etc/ssh/sshd_config').contains(f'^{pass_auth_config_name} no'), \
                f'{pass_auth_config_name} should be disabled (set to "no")'

    # TODO: verify logic, think if we should divide
    @pytest.mark.run_on(['rhel'])
    def test_auditd(self, host):
        """
        - Service should be running
        - Config files should have the correct MD5 checksums
        """
        if test_lib.is_rhel_atomic_host(host):
            pytest.skip('Not applicable to Atomic hosts')

        auditd_service = 'auditd'

        assert host.service(auditd_service).is_running, f'{auditd_service} expected to be running'

        rhel_version = float(host.system_info.release)
        checksums = self.__get_auditd_checksums_by_rhel_major_version(int(rhel_version))

        with host.sudo():
            for path, md5 in checksums.items():
                assert md5 == host.check_output(f'md5sum {path}'), f'Unexpected checksum for {path}'

    def __get_auditd_checksums_by_rhel_major_version(self, major_version):
        checksums_by_version = {
            '8': {
                '/etc/audit/auditd.conf': '7bfa16d314ddb8b96a61a7f617b8cca0',
                '/etc/audit/audit.rules': '795528bd4c7b4131455c15d5d49991bb'
            },
            '7': {
                '/etc/audit/auditd.conf': '29f4c6cd67a4ba11395a134cf7538dbd',
                '/etc/audit/audit.rules': 'f1c2a2ef86e5db325cd2738e4aa7df2c'
            }
        }

        return checksums_by_version[major_version]

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


class TestsCloudInit:
    @pytest.mark.run_on(['all'])
    def test_growpart_is_present_in_config(self, host):
        """
        Make sure there is growpart in cloud_init_modules group in "/etc/cloud/cloud.cfg".
        BugZilla 966888
        """
        assert host.file('/etc/cloud/cloud.cfg').contains('- growpart'), \
            'growpart must be present in cloud_init_modules'

    @pytest.mark.run_on(['rhel'])
    def test_wheel_group_not_set_to_default_user(self, host):
        """
        Make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg".
        BugZilla 1549638
        Customer Case 01965459
        """
        assert not host.file('/etc/cloud/cloud.cfg').contains('wheel'), \
            'wheel should not be configured as default_user group'


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

    @pytest.mark.run_on(['all'])
    def test_eth0_network_adapter_setup(self, host):
        """
        Make sure that eht0 default adapter is correctly setup:
            1. NETWORKING=yes in /etc/sysconfig/network
            2. DEVICE=eth0 in /etc/sysconfig/network-scripts/ifcfg-eth0
        """
        device_name = 'eth0'

        with host.sudo():
            assert host.file('/etc/sysconfig/network').contains('^NETWORKING=yes'), \
                'Invalid networking setup'

            device_config_path = f'/etc/sysconfig/network-scripts/ifcfg-{device_name}'

            assert host.file(device_config_path).contains(f'^DEVICE=[{device_name}|\"{device_name}\"]'), \
                f'Unexpected device name. Expected: "{device_name}"'


class TestsSecurity:
    @pytest.mark.run_on(['rhel'])
    def test_firewalld_is_disabled(self, host):
        """
        firewalld is not required in cloud because there are security groups or other security mechanisms.
        """
        assert not host.package('firewalld').is_installed, \
            'firewalld should not be installed in RHEL cloud images'
