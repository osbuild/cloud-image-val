import os
import time
import sshconf
import paramiko


def generate_ssh_key_pair(ssh_key_path):
    if os.path.exists(ssh_key_path):
        os.remove(ssh_key_path)

    os.system(f'ssh-keygen -f "{ssh_key_path}" -N "" -q')


def generate_instances_ssh_config(ssh_key_path, ssh_config_file, instances):
    if os.path.exists(ssh_config_file):
        os.remove(ssh_config_file)

    conf = sshconf.empty_ssh_config_file()

    for inst in instances.values():
        conf.add(inst['public_dns'],
                 Hostname=inst['public_dns'],
                 User=inst['username'],
                 Port=22,
                 IdentityFile=ssh_key_path,
                 StrictHostKeyChecking='no',
                 UserKnownHostsFile='/dev/null',
                 LogLevel='ERROR',
                 ConnectTimeout=30,
                 ConnectionAttempts=5)

    conf.write(ssh_config_file)


def wait_for_host_ssh_up(host_address, timeout_seconds):
    """
    Check if a given host is ready for SSH connection within a given number of seconds
    :param host_address: Host public DNS or IP address.
    :param timeout_seconds: The maximum number of seconds to check for SSH availability.
    :return: None
    """
    start_time = time.time()
    while time.time() < start_time + timeout_seconds:
        tick = time.time()
        if (os.system(f'ssh-keyscan "{host_address}" > /dev/null 2>&1') >> 8) == 0:
            print(f'{host_address} SSH is up! ({time.time() - start_time} seconds)')
            return
        else:
            time_diff_seconds = int(time.time() - tick)
            time.sleep(max(0, (1 - time_diff_seconds)))

    print(f'Timeout while waiting for {host_address} to be SSH-ready ({timeout_seconds} seconds).')
    print('AWS: Check if this account has the appropiate inbound rules for this region')
    exit(1)


def copy_file_to_host(host, local_file_path, destination_path):
    """
    Copies a local file to the remote host, in a given destination path.
    This test only works with testinfra's Paramiko backend.
    :param host: The host object from the pytest test case.
    :param local_file_path: The path of the local file that will be copied.
    :param destination_path: The destination path where the local file will be placed in the remote host.
    :return: None
    """
    sftp = host.backend.client.open_sftp()

    sftp.put(local_file_path, destination_path)
    sftp.close()


def add_ssh_keys_to_instances(instances):
    """
    Adding ssh public keys of team members to all instances authorized_keys.
    :param instances: Has all the instances needed information - 'public_dns', 'username' etc..
    :return: None
    """
    authorized_keys = "~/.ssh/authorized_keys"
    ssh_identity_file = '/tmp/ssh_key'
    team_ssh_keys_file = 'schutzbot/team_ssh_keys.txt'
    ssh_client = get_ssh_client()

    for instance in instances.values():
        ssh_client.connect(
            hostname=instance['public_dns'],
            username=instance['username'],
            key_filename=ssh_identity_file
        )

        with open(team_ssh_keys_file, 'r') as f:
            team_ssh_keys = f.read()
            cmd = f"echo '{team_ssh_keys}' >> {authorized_keys}"
            ssh_client.exec_command(cmd)
        ssh_client.close()


def get_ssh_client():
    ssh_client = paramiko.client.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return ssh_client
