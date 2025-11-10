import os
import re
import time
import pytest
from packaging import version
from test_suite.generic import helpers

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

        helpers.check_avc_denials(host)

    @pytest.mark.run_on(['all'])
    def test_bash_history_is_empty(self, host):
        users = [host.user().name, 'root']

        for u in users:
            file_path = f'/home/{u}/.bash_history'
            bash_history_file = host.file(file_path)
            if bash_history_file.exists:
                file_content_length = len(bash_history_file.content_string)
                assert file_content_length == 0, f'{file_path} must be empty or nonexistent'

    @pytest.mark.run_on(['rhel'])
    def test_blocklist(self, host, instance_data):
        """
        Check that a list of modules are disabled - not loaded.
        """
        modules = ['nouveau', 'amdgpu']

        if instance_data['cloud'] == 'azure':
            modules.extend(['acpi_cpufreq', 'floppy', 'intel_uncore', 'intel_cstate', 'skylake-edac'])

        # blocklist_conf = '/usr/lib/modprobe.d/blacklist-{module}.conf'
        # files_to_check = [blocklist_conf.format(module=modules[x]) for x in range(len(modules))]
        # blocklist_conf_strings = ['blacklist ' + x for x in modules]

        loaded_modules = []
        with host.sudo():
            for module in modules:
                if host.run(f'lsmod | grep -w {module}').stdout:
                    loaded_modules.append(module)
            assert not loaded_modules, \
                f"The following modules should not be loaded: {', '.join(loaded_modules)}"

            # ToDo: CLOUDX-1518
            # for file, str_to_check in zip(files_to_check, blocklist_conf_strings):
            #    assert host.file(file).exists, f'file "{file}" does not exist'
            #    assert host.file(file).contains(str_to_check), \
            #        f'{str_to_check} is not blocklisted in "{file}"'

    # TODO: Confirm if this test should be run in non-RHEL images
    @pytest.mark.run_on(['rhel'])
    def test_username(self, host, instance_data):
        for user in ['fedora', 'cloud-user']:
            with host.sudo():
                assert not host.user(user).exists, 'Unexpected username in instance'

            assert host.check_output('whoami') == instance_data['username']

    @pytest.mark.run_on(['rhel'])
    def test_cmdline_console_and_params(self, host, instance_data):
        """
        Verify the console and other required parameters in the kernel command line.
        """
        file_to_check = '/proc/cmdline'

        expected_config = []

        # Define expected console based on architecture and platform
        if host.system_info.arch == 'aarch64' and instance_data['cloud'] == 'azure':
            expected_config.append('console=ttyAMA0')
        else:
            expected_config.append('console=ttyS0')

        # Add Azure-specific parameters
        if host.system_info.arch == 'x86_64' and instance_data['cloud'] == 'azure':
            expected_config.extend(['earlyprintk=ttyS0', 'rootdelay=300'])

        # Add RHEL 9.6+ specific parameter
        if version.parse(host.system_info.release) >= version.parse('9.6') and \
                instance_data['cloud'] == 'azure':
            expected_config.append('nvme_core.io_timeout=240')

        # CVM specific parameters
        if test_lib.is_rhel_cvm(host):
            expected_config = ['console=tty0', 'console=ttyS0']

        with host.sudo():
            for item in expected_config:
                assert host.file(file_to_check).contains(item), \
                    f'{item} was expected in {file_to_check}'

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
        rpm_to_check = 'redhat-release'

        with host.sudo():
            host.run_test(f'rpm -q {rpm_to_check}')
            cert_output = host.check_output('rct cat-cert /etc/pki/product-default/*.pem')

            in_product_section = False

            for line in cert_output.splitlines():
                trimmed_line = line.strip()

                # 1. Look for the start of the Product section
                if trimmed_line == 'Product:':
                    in_product_section = True
                    continue

                # 2. If we are in the Product section, look for 'Version:'
                if in_product_section and trimmed_line.startswith('Version:'):
                    product_version = trimmed_line.split(':', 1)[1].strip()

            assert str(system_release) == product_version, \
                'Inconsistent version in pki certificate'

            sub_man_installed = host.check_output('subscription-manager list --installed | grep Version')
            sub_man_version = sub_man_installed.split(':', 1)[1].strip()

            assert str(system_release) in sub_man_version, \
                'Inconsistent version in RHSM list --installed'

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

    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_release_version(self, host):
        """
        Check if release package version matches /etc/redhat-release
        """
        system_release = version.parse(host.system_info.release)

        release_file = 'redhat-release'
        if host.system_info.distribution == 'fedora':
            release_file = 'fedora-release'

        with host.sudo():
            command_to_run = "rpm -q --qf '%{VERSION}' --whatprovides " + release_file
            raw_package_version = host.check_output(command_to_run)
            print(f"DEBUG: Raw RPM output for package version: '{raw_package_version}'")
            package_release = version.parse(raw_package_version)

        assert system_release == package_release, \
            f'Product version ({system_release}) does not match package release version'

    @pytest.mark.run_on(['rhel'])
    def test_root_is_locked(self, host):
        """
        Check if root account is locked
        """
        with host.sudo():
            if version.parse(host.system_info.release).major >= 10:
                result = host.run('passwd -S root | grep -q L').rc
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
    @pytest.mark.usefixtures('rhel_cvm_skip')
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

    @pytest.mark.run_on(['all'])
    @pytest.mark.usefixtures('rhel_cvm_skip')
    def test_boot_mount_presence(self, host, instance_data):
        """
        The /boot mount exists if
            * 8.y and aarch64
            * 9.y
            * 10.y and Azure and LVM
            * Fedora
        In all other cases the /boot mount doesn't exist on a system.
        If /boot exists it should be at least 960Mib (lower threshold of 1024MiB)

        JIRA: CLOUDX-930, CLOUDX-980
        """

        release_major = version.parse(host.system_info.release).major
        is_aarch64 = host.system_info.arch == 'aarch64'
        is_azure = instance_data['cloud'] == 'azure'
        lvm_check = host.run("lsblk -f | grep LVM").rc == 0
        is_fedora = host.system_info.distribution == 'fedora'

        if (
           (release_major == 8 and is_aarch64)
           or (release_major == 9)
           or (release_major >= 10 and is_azure and lvm_check)
           or is_fedora
           ):
            assert host.mount_point("/boot").exists, "/boot mount is missing"

            result = host.run("df --block-size=1 /boot | tail -1")
            parts = result.stdout.split()
            total_bytes = int(parts[1])
            min_size_mib = 960
            required_size = min_size_mib * 1024 * 1024  # 960MiB
            assert total_bytes >= required_size, \
                f'Partition /boot is too small: {total_bytes} bytes'
        else:
            assert not host.mount_point("/boot").exists, "/boot mount is detected"

    @pytest.mark.run_on(['rhel'])
    @pytest.mark.usefixtures('rhel_cvm_skip')
    def test_net_ifnames_usage(self, host, instance_data):
        """
        CLOUDX-979, RHELPLAN-103894 drop net.ifnames=0 kernel boot parameter on RHEL10 and later
        BZ1859926 ifnames should be specified on AWS for RHEL9 and earlier releases
        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
        """
        kernel_boot_param = 'net.ifnames=0'
        cmdline_file = '/proc/cmdline'
        grub_default_file = '/etc/default/grub'
        system_release_major = version.parse(host.system_info.release).major

        if system_release_major >= 10:
            assert not host.file(cmdline_file).contains(kernel_boot_param), \
                f'There is unexpected {kernel_boot_param} in kernel real-time boot parameters.'

            assert not host.file(grub_default_file).contains(kernel_boot_param), \
                f'{kernel_boot_param} is found in {grub_default_file}!'
        else:
            if instance_data['cloud'] == 'aws':
                with host.sudo():
                    assert host.file(cmdline_file).contains(kernel_boot_param), \
                        'ifnames expected to be specified'

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
        if test_lib.is_rhel_saphaus(host):
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
        Verify there is only one key in /root/.ssh/authorized_keys
        BugZilla 2127969
        """
        with host.sudo():
            debug = host.file('/root/.ssh/authorized_keys').content_string
            print(debug)

            authorized_keys_lines = host.check_output('cat /root/.ssh/authorized_keys | wc -l')
            assert authorized_keys_lines == '1', 'There is more than one public key in authorized_keys'

    @pytest.mark.run_on(['rhel'])
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
        file_to_check = '/etc/yum/pluginconf.d/langpacks.conf'

        with host.sudo():
            assert not host.file(file_to_check).exists, \
                f'{file_to_check} should not exist in RHEL-8 and above'

    @pytest.mark.run_on(['all'])
    def test_timezone_is_utc(self, host):
        """
        Check that the default timezone is set to UTC.
        BugZilla 1187669
        """
        timezone = host.check_output('date +%Z').strip()
        assert timezone == 'UTC', f'Unexpected timezone: {timezone}. Expected to be UTC'

    @pytest.mark.run_on(['>=rhel9.6', 'rhel10'])
    def test_bootc_installed(self, host):
        """
        Verify the system-reinstall-bootc package is installed
        JIRA: CLOUDX-1267
        """

        with host.sudo():
            print('rpm -q output: ')
            print(host.run('rpm -q system-reinstall-bootc').stdout)
            print('yum search output: ')
            print(host.run('yum search system-reinstall-bootc').stdout)
            assert host.package("system-reinstall-bootc").is_installed, \
                'System-reinstall-bootc package expected to be installed in RHEL >= 9.6, 10.0'

    @pytest.mark.run_on(['rhel'])
    def test_logging_cfg(self, host):
        """
        Check /etc/cloud/cloud.cfg.d/05_logging.cfg
        """
        file_to_check = '/etc/cloud/cloud.cfg.d/05_logging.cfg'
        local_file = 'data/generic/05_logging.cfg'

        assert test_lib.compare_local_and_remote_file(host, local_file, file_to_check), \
            f'{file_to_check} has unexpected content'

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
    def test_services_running(self, host, instance_data):
        """
        Verify the necessary services are running
        """
        service_list = [
            'cloud-init-local', 'cloud-init',
            'cloud-config', 'cloud-final', 'sshd',
        ]

        if instance_data['cloud'] == 'azure':
            service_list.append('waagent')
            if not test_lib.is_rhel_cvm(host):
                service_list.append('hypervkvpd')

        with host.sudo():
            for service in service_list:
                assert host.service(service).is_running

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
            }
        }

        auditd_service = 'auditd'

        assert host.service(
            auditd_service).is_running, f'{auditd_service} expected to be running'

        system_release = version.parse(host.system_info.release)
        if system_release >= version.parse('9.4'):
            checksums = checksums_by_version['9.4+']
        elif version.parse('9.0') > system_release >= version.parse('8.10'):
            checksums = checksums_by_version['8.10+']
        else:
            checksums = checksums_by_version['8.6+']

        with host.sudo():
            for path, md5 in checksums.items():
                assert md5 in host.check_output(
                    f'md5sum {path}'), f'Unexpected checksum for {path}'

    @pytest.mark.pub
    @pytest.mark.run_on(['all'])
    def test_pkg_signature_and_gpg_keys(self, host):
        """
        Checks that packages have a valid GPG signature,
        either SIGPGP or RSAHEADER, and that a single GPG key is used.
        """
        with host.sudo():
            # Query all installed RPMs and their GPG signature status
            rpm_signature_query_cmd = (
                "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} "
                "SIGPGP:%{SIGPGP:pgpsig} RSAHEADER:%{RSAHEADER:pgpsig}\\n'"
            )
            filter_gpg_pubkey = f"{rpm_signature_query_cmd} | grep -v gpg-pubkey"

            # Get all lines for software packages
            package_signature_lines = host.check_output(filter_gpg_pubkey).splitlines()

            unsigned_packages = []
            for line in package_signature_lines:
                if 'SIGPGP:(none)' in line and 'RSAHEADER:(none)' in line:
                    unsigned_packages.append(line)

            # Construct a detailed error message if unsigned packages are found.
            error_message = (
                "ERROR: The following software packages were found to be installed "
                "without a valid GPG signature:\n"
                f"{chr(10).join(unsigned_packages)}\n"
                "This indicates that signature verification might be disabled, or "
                "packages were installed with '--nogpgcheck'. "
                "Ensure 'gpgcheck=1' is set for all enabled repositories and "
                "packages are from trusted sources."
            )

            # Assert that no unsigned packages were found.
            assert not unsigned_packages, error_message

            # check use only one keyid
            rpm_signatures_cmd = (
                "rpm -qa --qf '%{NAME} %{SIGPGP:pgpsig} %{RSAHEADER:pgpsig}\\n'"
            )
            key_ids_command = ' '.join([rpm_signatures_cmd,
                                        "| grep -vE '(gpg-pubkey|rhui)'",
                                        "| awk '{if ($2 != \"(none)\") print $2; else if ($3 != \"(none)\") print $3}'",
                                        "| awk -F'Key ID ' '{print $2}'",
                                        "| sort | uniq | wc -l"])
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

    # TODO: Refactor this test case. E.g. divide it by type of image and version
    @pytest.mark.run_on(['rhel'])
    def test_required_packages_are_installed(self, host, instance_data):
        """
        Some pkgs are required in EC2.
        https://kernel.googlesource.com/pub/scm/boot/dracut/dracut/+/18e61d3d41c8287467e2bc7178f32d188affc920%5E!/

        dracut-nohostonly -> dracut-config-generic
        dracut-norescue   -> dracut

        BugZilla 1822853, 1823315: Starting from RHEL 8.5, NetworkManager-cloud-setup package was added
        """
        if test_lib.is_rhel_cvm:
            pytest.skip("Not applicable to CVM images")

        required_pkgs = [
            'kernel', 'yum-utils', 'redhat-release', 'redhat-release-eula',
            'cloud-init', 'tar', 'rsync', 'dhcp-client', 'NetworkManager',
            'cloud-utils-growpart', 'gdisk', 'insights-client', 'chrony',
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

        if instance_data['cloud'] == 'azure':
            required_pkgs.extend(['WALinuxAgent', 'firewalld'])

            if not test_lib.is_rhel_cvm(host):
                required_pkgs.extend(['hypervkvpd', 'hyperv-daemons-license', 'hypervvssd'
                                      'hyperv-daemons'])
                if host.system_info.arch != 'aarch64':
                    required_pkgs.append('hypervfcopyd')

        missing_pkgs = [pkg for pkg in required_pkgs if not host.package(pkg).is_installed]

        assert len(missing_pkgs) == 0, f'Missing packages: {", ".join(missing_pkgs)}'

    @pytest.mark.pub
    @pytest.mark.run_on(['rhel'])
    def test_yum_package_install_kernel_debug(self, host):
        """
        BugZilla: 2117700
        Test that kernel-debug and kernel-debug-devel matching current kernel version are available in repo
        Open Question: which versions does this test apply? using all rhel versions for now
        """
        print(f"kernel version: {host.check_output('uname -r')}")

        with host.sudo():
            assert host.run_test('yum -y install kernel-debug-devel-$(uname -r)')
            assert host.run_test('yum -y install kernel-debug-$(uname -r)')

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
        system_release = version.parse(host.system_info.release)

        if distro == 'fedora' or \
           (distro == 'centos' and release_major >= 9) or \
           (distro == 'rhel' and system_release >= version.parse('9.8')):
            # Strict permissions
            expected_mode = 0o600

        print(host.run('rpm -q cloud-init').stdout)

        for file in files_to_check:
            print(host.run(f'stat -c "%a %n" /etc/ssh/{file}*').stdout)
            if host.file(f'/etc/ssh/{file}').exists:
                assert host.file(f'/etc/ssh/{file}').mode == expected_mode, \
                    'ssh files permissions are not set correctly'

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
@pytest.mark.usefixtures('rhel_aws_marketplace_only')
class TestsSubscriptionManager:
    def test_subscription_manager_auto(self, host, instance_data):
        """
        BugZilla 8.4: 1932802, 1905398
        BugZilla 7.9: 2077086, 2077085
        """

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
@pytest.mark.usefixtures('rhel_aws_marketplace_only')
class TestsYum:
    # TODO: confirm if this test needs to be deprecated
    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_yum_repoinfo(self, host):
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

    @pytest.mark.run_on(['rhel', 'centos'])
    def test_eth0_network_adapter_setup(self, host, instance_data):
        """
        Make sure that eht0 default adapter is correctly setup:
            1. NETWORKING=yes in /etc/sysconfig/network
            2. For major_release<10: eth0 in /etc/sysconfig/network-scripts/ifcfg-eth0
            3. For major_release>=10: exists /etc/NetworkManager/system-connections/*.nmconnection

        Does not apply to >fedora35: https://fedoramagazine.org/converting-networkmanager-from-ifcfg-to-keyfiles/
        """
        if instance_data['cloud'] == 'azure' and \
                version.parse(host.system_info.release).major == 9:
            pytest.skip('Skipping due to cloud-init known issue in RHEL-9.x. See COMPOSER-2437 for details.')

        device_name = 'eth0'
        device_config_path = f'/etc/sysconfig/network-scripts/ifcfg-{device_name}'
        keyfile_plugin = '/etc/NetworkManager/system-connections/*.nmconnection'

        with host.sudo():
            assert host.file('/etc/sysconfig/network').contains('^NETWORKING=yes'), \
                'Invalid networking setup'

            release_major = version.parse(host.system_info.release).major

            if release_major < 10:
                assert host.file(device_config_path).contains(f'^DEVICE=[{device_name}|\"{device_name}\"]'), \
                    f'Unexpected device name. Expected: "{device_name}"'
            else:
                keyfile = host.check_output(f"ls {keyfile_plugin} 2>/dev/null || true")
                assert keyfile != "", \
                    f'There is no keyfile plugin as "{keyfile_plugin}"'

    @pytest.mark.run_on(['rhel'])
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

    @pytest.mark.run_on(['rhel', 'fedora'])
    def test_etc_machine_id_permissions(self, host, instance_data):
        """
        Check that /etc/machine-id permissions are 444.
        Bugzilla: 2221269
        """
        assert host.file('/etc/machine-id').mode == 0o444, 'Expected 444 permissions for /etc/machine-id'


@pytest.mark.order(1)
@pytest.mark.run_on(['rhel'])
class TestsAuthConfig:
    @pytest.fixture(autouse=True)
    def skip_on_aws(self, host, instance_data):
        if instance_data['cloud'] == 'aws':
            pytest.skip("Auth test cases don't apply to AWS.")

    def test_authselect_has_no_config(self, host):
        """
        Check authselect current

        RHELBU-2336 local profile is default for RHEL10 and later
        """
        authselect_profile = host.run('authselect current').stdout
        if version.parse(host.system_info.release).major >= 10:
            expected_profile = 'Profile ID: local\nEnabled features: None\n'
        else:
            expected_profile = "No existing configuration detected."

        assert expected_profile in authselect_profile, \
            f'authselect is expected to have {expected_profile} configuration'

    def test_authselect_conf_files(self, host):
        authselect_dir = '/etc/authselect/'
        if version.parse(host.system_info.release).major < 10:
            expected_config_files = ['custom', 'user-nsswitch.conf', ]
        else:
            expected_config_files = [
                'authselect.conf', 'custom', 'dconf-db', 'dconf-locks',
                'fingerprint-auth', 'nsswitch.conf', 'password-auth',
                'postlogin', 'smartcard-auth', 'system-auth'
            ]
        current_files = host.file(authselect_dir).listdir()

        print(current_files)

        assert current_files == expected_config_files, \
            f'Unexpected result when listing files under {authselect_dir}'

        authselect_custom_dir = '/etc/authselect/custom/'
        assert len(host.file(authselect_custom_dir).listdir()) == 0, \
            f'Unexpected files found under {authselect_custom_dir}.' \
            f'This directory should be empty'

    @pytest.mark.exclude_on(['>=rhel10.0'])
    def test_fingerprint_auth(self, host):
        """
        Check file /etc/pam.d/fingerprint-auth
        """
        self.__check_pam_d_file_content(host, 'fingerprint-auth')

    @pytest.mark.exclude_on(['>=rhel10.0'])
    def test_password_auth(self, host):
        """
        Check file /etc/pam.d/password-auth
        """
        self.__check_pam_d_file_content(host, 'password-auth')

    @pytest.mark.exclude_on(['>=rhel10.0'])
    def test_postlogin(self, host):
        """
        Check file /etc/pam.d/postlogin
        """
        self.__check_pam_d_file_content(host, 'postlogin')

    @pytest.mark.exclude_on(['>=rhel10.0'])
    def test_smartcard_auth(self, host):
        """
        Check file /etc/pam.d/smartcard-auth
        Bugzilla: 1983683
        """
        if version.parse(host.system_info.release) == version.parse('8.10'):
            local_file = 'data/generic/smartcard-auth_rhel8.10'
            file_to_check = '/etc/pam.d/smartcard-auth'
            assert test_lib.compare_local_and_remote_file(host, local_file, file_to_check), \
                f'{file_to_check} has unexpected content'
        else:
            self.__check_pam_d_file_content(host, 'smartcard-auth')

    @pytest.mark.exclude_on(['>=rhel10.0'])
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
    @pytest.mark.usefixtures('rhel_cvm_skip')
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


@pytest.mark.order(2)
@pytest.mark.usefixtures('rhel_sap_only')
class TestSAP:
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


@pytest.mark.order(4)
class TestsHA:
    @pytest.mark.run_on(['rhel'])
    @pytest.mark.usefixtures('rhel_aws_marketplace_only')
    def test_ha_specific_script(self, host, instance_data):
        """
        Verify HA functionality on RHEL HA and RHEL SAP HA and US images
        Skip AWS 3p amis since they don't have billing codes and
        and therefore no RHUI access in stage.
        """
        # Run on HA or SAP+HA images only
        is_ha = test_lib.is_rhel_high_availability(host)
        is_sap_ha = test_lib.is_rhel_saphaus(host)
        if not (is_ha or is_sap_ha):
            pytest.skip("Not a HA or SAP+HA image.")

        release_major = version.parse(host.system_info.release).major
        if instance_data['cloud'] == 'azure' and release_major == 8:
            pytest.skip("Skip due to no azure-cli on RHEL8 Azure")

        cloud = instance_data['cloud'].lower()
        local_file_path = f'scripts/rhel-ha-{cloud}-check.sh'
        expected_success_message = "HA check passed successfully."

        result = None
        try:
            result = test_lib.run_local_script_in_host(host, local_file_path)
        finally:
            if result and result.rc != 0:
                print(f"Script stdout:\n{result.stdout}")
                print(f"Script stderr:\n{result.stderr}")

        assert result is not None, "HA check script did not return a result."
        assert result.rc == 0, \
            f"HA check script for cloud '{cloud}' failed with rc={result.rc}"
        assert expected_success_message in result.stdout, \
            "There is no the expected success message in the script stdout."
