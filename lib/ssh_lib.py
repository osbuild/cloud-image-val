import os
import time
import sshconf


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
                 LogLevel='ERROR')

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
