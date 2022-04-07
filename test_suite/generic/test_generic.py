class TestsGeneric:
    def test_bash_history_empty(self, host):
        users = [host.user().name, 'root']

        for u in users:
            file_path = f'/home/{u}/.bash_history'
            bash_history_file = host.file(file_path)
            if bash_history_file.exists:
                file_content_length = len(bash_history_file.content_string)
                assert file_content_length == 0, f'{file_path} must be empty or nonexistent'


class TestsSecurity:
    def test_firewalld_is_disabled(self, host):
        product_version = 7.0
        if float(host.system_info.release) < product_version:
            for s in ['iptables', 'ip6tables']:
                assert not host.service(s).is_enabled,\
                    f'{s} service should be disabled in RHEL below {product_version}'
        else:
            assert not host.package('firewalld').is_installed,\
                f'firewalld should not be installed in cloud images for RHEL {product_version} and above'
