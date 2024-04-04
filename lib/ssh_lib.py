import os
import time
import sshconf

from threading import Thread


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
    key_paths = __get_team_ssh_key_paths()

    threads = []
    for inst in instances.values():
        t = Thread(target=__copy_team_ssh_keys_to_instance,
                   args=[inst, key_paths])
        t.start()
        threads.append(t)

    [t.join() for t in threads]


def __get_team_ssh_key_paths():
    keys_dir = 'schutzbot/team_ssh_keys'

    return [os.path.join(keys_dir, p) for p in os.listdir(keys_dir)]


def __copy_team_ssh_keys_to_instance(instance, key_file_paths):
    instance_address = instance['public_dns']
    username = instance['username']

    print(f'[{instance_address}] Copying public SSH key(s)...')

    for path in key_file_paths:
        ssh_copy_id_command = (f'ssh-copy-id -f -i "{path}" '
                               f'-o "StrictHostKeyChecking=no IdentityFile=/tmp/ssh_key" '
                               f'{username}@{instance_address} 2>&1')
        command = os.popen(ssh_copy_id_command, 'r')
        command_output = command.read()

        if command.close() is None:
            print(f'[{instance_address}] Public SSH key {path} copied successfully!')
        else:
            print(f'[{instance_address}] WARNING: Could not copy public SSH key {path}: {command_output}')
