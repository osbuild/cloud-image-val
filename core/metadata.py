from __future__ import annotations

import functools
import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Union

import jsonschema
import sshconf

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / 'schemas' / 'civ-instances.schema.json'

_REQUIRED_FIELDS = {'name', 'address', 'username', 'cloud', 'image'}
_OPTIONAL_FIELDS = {'region', 'distro', 'version', 'arch', 'image_id', 'instance_type'}


@dataclass
class InstanceMetadata:
    name: str
    address: str
    username: str
    cloud: str
    image: Union[str, dict[str, Any]]
    region: str = ""
    distro: str = ""
    version: str = ""
    arch: str = ""
    image_id: str = ""
    instance_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            k: v for k, v in asdict(self).items()
            if k in _REQUIRED_FIELDS or v != ""
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InstanceMetadata:
        for field_name in _REQUIRED_FIELDS:
            if field_name not in data:
                raise ValueError(f"Missing required field: '{field_name}'")

        for field_name in _REQUIRED_FIELDS - {'image'}:
            if not isinstance(data[field_name], str):
                raise TypeError(
                    f"Field '{field_name}' must be str, got {type(data[field_name]).__name__}"
                )

        if not isinstance(data['image'], (str, dict)):
            raise TypeError(
                f"Field 'image' must be str or dict, got {type(data['image']).__name__}"
            )

        for field_name in _OPTIONAL_FIELDS:
            if field_name in data and not isinstance(data[field_name], str):
                raise TypeError(
                    f"Field '{field_name}' must be str, got {type(data[field_name]).__name__}"
                )

        known_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


@functools.lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    with open(_SCHEMA_PATH) as f:
        return json.load(f)


def write_instances_json(
    instances: dict[str, InstanceMetadata],
    path: str,
) -> None:
    document = {key: inst.to_dict() for key, inst in instances.items()}

    schema = _load_schema()
    jsonschema.validate(document, schema)

    with open(path, 'w') as f:
        json.dump(document, f, indent=4)


def write_ssh_config(
    instances: dict[str, InstanceMetadata],
    ssh_key_path: str,
    config_path: str,
) -> None:
    if os.path.exists(config_path):
        os.remove(config_path)

    # Uses inst.address as the SSH Host identifier, matching the original
    # ssh_lib.py behavior. If two instances share the same address, the
    # second entry will overwrite the first in the config file.
    conf = sshconf.empty_ssh_config_file()
    for inst in instances.values():
        conf.add(
            inst.address,
            Hostname=inst.address,
            User=inst.username,
            Port=22,
            IdentityFile=ssh_key_path,
            StrictHostKeyChecking="no",
            UserKnownHostsFile="/dev/null",
            LogLevel="ERROR",
            ConnectTimeout=30,
            ConnectionAttempts=5,
        )

    conf.write(config_path)


def set_civ_env_vars(
    instances: dict[str, InstanceMetadata],
    json_path: str,
    ssh_config_path: str,
) -> None:
    if instances:
        clouds = {inst.cloud for inst in instances.values()}
        if len(clouds) > 1:
            raise ValueError(f"All instances must share the same cloud, got: {sorted(clouds)}")
        cloud = clouds.pop()
    else:
        cloud = ""
    os.environ['CIV_CLOUD'] = cloud
    os.environ['CIV_INSTANCES_JSON'] = json_path
    os.environ['CIV_INSTANCES_COUNT'] = str(len(instances))
    os.environ['CIV_SSH_CONFIG'] = ssh_config_path
