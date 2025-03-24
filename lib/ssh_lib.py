import os
import time
import sshconf

from threading import Thread

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_ssh_key_pair(identity_file):
    """
    Generates an SSH key pair and writes them to the specified identity file.

    :param identity_file: The path where the private key will be written.
    :return: A tuple containing the paths of the private and public keys.
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Write private key to file in PEM format
    with open(identity_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Generate public key
    public_key = private_key.public_key()

    # Write public key to file in OpenSSH format
    with open(identity_file + '.pub', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ))

    print(f"Generated SSH keys: {identity_file} and {identity_file}.pub")
    return identity_file, identity_file + '.pub'


def generate_instances_ssh_config(ssh_key_path, ssh_config_file, instances):
    if os.path.exists(ssh_config_file):
        os.remove(ssh_config_file)

    conf = sshconf.empty_ssh_config_file()
    for inst in instances.values():
        conf.add(
            inst["address"],
            Hostname=inst["address"],
            User=inst["username"],
            Port=22,
            IdentityFile=ssh_key_path,
            StrictHostKeyChecking="no",
            UserKnownHostsFile="/dev/null",
            LogLevel="ERROR",
            ConnectTimeout=30,
            ConnectionAttempts=5,
        )

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
            print(f"{host_address} SSH is up! ({time.time() - start_time} seconds)")
            return
        else:
            time_diff_seconds = int(time.time() - tick)
            time.sleep(max(0, (1 - time_diff_seconds)))

    print(
        f"Timeout while waiting for {host_address} to be SSH-ready ({timeout_seconds} seconds)."
    )
    print("AWS: Check if this account has the appropiate inbound rules for this region")
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


def add_ssh_keys_to_instances(instances, ssh_config_file):
    team_ssh_keys = __get_team_ssh_keys_by_path()

    print(f'Team public SSH key(s) to copy: {", ".join(list(team_ssh_keys.keys()))}')

    threads = []
    for inst in instances.values():
        t = Thread(
            target=__copy_team_ssh_keys_to_instance,
            args=[inst, ssh_config_file, team_ssh_keys],
        )
        t.start()
        threads.append(t)

    [t.join() for t in threads]


def __get_team_ssh_keys_by_path():
    keys_dir = "schutzbot/team_ssh_keys"

    keys = {}
    for p in os.listdir(keys_dir):
        key_file_path = os.path.join(keys_dir, p)
        with open(key_file_path, "r") as f:
            keys[key_file_path] = f.read()

    return keys


def __copy_team_ssh_keys_to_instance(instance, ssh_config_file, team_ssh_keys):
    auth_keys = "~/.ssh/authorized_keys"
    instance_address = instance["address"]
    username = instance["username"]

    composed_echo_command = ";".join(
        [f'echo "{k}" >> {auth_keys}' for k in team_ssh_keys.values()]
    )

    ssh_command = (
        f'ssh -F "{ssh_config_file}" '
        f'{username}@{instance_address} "{composed_echo_command}" > /dev/null 2>&1'
    )

    if (os.system(ssh_command) >> 8) == 0:
        print(f"[{instance_address}] Public SSH key(s) copied successfully!")
    else:
        print(f"[{instance_address}] WARNING: Could not copy public SSH key(s)")
