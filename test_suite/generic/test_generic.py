class TestsGeneric:
    def test_passwd_file(self, host):
        passwd = host.file("/etc/passwd")
        assert passwd.contains("root")
        assert passwd.user == "root"
        assert passwd.group == "root"
        assert passwd.mode == 0o644

    def test_bash_history_empty(self, host):
        users = [host.user().name, 'root']

        for u in users:
            file_path = f'/home/{u}/.bash_history'
            bash_history_file = host.file(file_path)
            if bash_history_file.exists:
                file_content_length = len(bash_history_file.content_string)
                assert file_content_length == 0, f'{file_path} must be empty or nonexistent'


class TestsNetworking:
    def test_curl_is_installed(self, host):
        curl = host.package("curl")
        assert curl.is_installed
