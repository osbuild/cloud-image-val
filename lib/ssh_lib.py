from fabric import Connection


class SSHAgent:
    def __init__(self, hostname, username, ssh_keyfile):
        self.hostname = hostname
        self.username = username
        self.ssh_keyfile = ssh_keyfile

        self.connection = Connection(
            host=self.hostname,
            user=self.username,
            connect_kwargs={'key_filename': self.ssh_keyfile}
        )

    def __del__(self):
        self.connection.close()

    def run_command(self, command):
        return self.connection.run(command=command, hide=True)


if __name__ == '__main__':
    host = '<hostname>'
    user = '<ssh_user>'
    key_file = '<local_path_to_pem_ssh_key>'

    ssh_agent = SSHAgent(host, user, key_file)
    result = ssh_agent.run_command('echo "hello world!"')

    print(result)
