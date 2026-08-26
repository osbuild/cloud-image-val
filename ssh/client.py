import os
import subprocess
import time

from threading import Thread

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_ssh_key_pair(identity_file: str) -> tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(identity_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    os.chmod(identity_file, 0o600)

    public_key = private_key.public_key()

    with open(identity_file + ".pub", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )

    print(f"Generated SSH keys: {identity_file} and {identity_file}.pub")
    return identity_file, identity_file + ".pub"


def wait_for_host_ssh_up(host_address: str, timeout_seconds: int) -> None:
    start_time = time.time()
    while time.time() < start_time + timeout_seconds:
        tick = time.time()
        result = subprocess.run(
            ["ssh-keyscan", host_address],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
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


def _get_team_ssh_keys_by_path() -> dict[str, str]:
    keys_dir = "schutzbot/team_ssh_keys"

    keys: dict[str, str] = {}
    for p in os.listdir(keys_dir):
        key_file_path = os.path.join(keys_dir, p)
        with open(key_file_path, "r") as f:
            keys[key_file_path] = f.read()

    return keys


def _copy_team_ssh_keys_to_instance(
    instance: dict[str, str],
    ssh_config_file: str,
    team_ssh_keys: dict[str, str],
) -> None:
    auth_keys = "~/.ssh/authorized_keys"
    instance_address = instance["address"]
    username = instance["username"]

    composed_echo_command = ";".join(
        [f'echo "{k}" >> {auth_keys}' for k in team_ssh_keys.values()]
    )

    result = subprocess.run(
        [
            "ssh",
            "-F", ssh_config_file,
            f"{username}@{instance_address}",
            composed_echo_command,
        ],
        capture_output=True,
    )

    success = result.returncode == 0

    assert success, f"[{instance_address}] ERROR: Could not copy public SSH key(s)"
    print(f"[{instance_address}] Public SSH key(s) copied successfully!")


def add_ssh_keys_to_instances(instances: dict, ssh_config_file: str) -> None:
    team_ssh_keys = _get_team_ssh_keys_by_path()

    print(f'Team public SSH key(s) to copy: {", ".join(list(team_ssh_keys.keys()))}')

    threads: list[Thread] = []
    for inst in instances.values():
        t = Thread(
            target=_copy_team_ssh_keys_to_instance,
            args=[inst, ssh_config_file, team_ssh_keys],
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
