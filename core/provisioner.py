from __future__ import annotations

import os
from pprint import pprint

from cloud.opentofu.opentofu_configurator import OpenTofuConfigurator
from cloud.opentofu.opentofu_controller import OpenTofuController
from core.config import CoreConfig
from core.metadata import InstanceMetadata, write_instances_json, write_ssh_config
from ssh.client import add_ssh_keys_to_instances, generate_ssh_key_pair


class Provisioner:
    def __init__(self, config: CoreConfig) -> None:
        self.config = config
        self._controller: OpenTofuController | None = None
        self._configurator: OpenTofuConfigurator | None = None

    def provision(self) -> dict[str, InstanceMetadata]:
        generate_ssh_key_pair(self.config.ssh_identity_file)

        self._configurator = OpenTofuConfigurator(
            ssh_key_path=self.config.ssh_pub_key_file,
            resources_path=self.config.resources_file,
            config=self.config.to_dict(),
        )
        self._configurator.configure_from_resources_json()

        if self.config.debug:
            self._configurator.print_configuration()

        self._controller = OpenTofuController(
            self._configurator, self.config.debug,
        )
        self._controller.create_infra()

        raw_instances = self._controller.get_instances()

        if self.config.debug:
            pprint(raw_instances)

        instances = {
            key: InstanceMetadata.from_dict(data)
            for key, data in raw_instances.items()
        }

        write_instances_json(instances, self.config.instances_json)
        write_ssh_config(
            instances,
            ssh_key_path=self.config.ssh_identity_file,
            config_path=self.config.ssh_config_file,
        )

        return instances

    def get_instances(self) -> dict[str, InstanceMetadata]:
        self._configurator = OpenTofuConfigurator(
            ssh_key_path=self.config.ssh_pub_key_file,
            resources_path=self.config.resources_file,
            config=self.config.to_dict(),
        )

        self._controller = OpenTofuController(
            self._configurator, self.config.debug,
        )

        raw_instances = self._controller.get_instances()

        return {
            key: InstanceMetadata.from_dict(data)
            for key, data in raw_instances.items()
        }

    def cleanup(self) -> None:
        try:
            if self._controller is not None:
                self._controller.destroy_infra()
        finally:
            if not self.config.debug:
                for path in (
                    self.config.ssh_identity_file,
                    self.config.ssh_pub_key_file,
                    self.config.ssh_config_file,
                    self.config.instances_json,
                ):
                    try:
                        os.remove(path)
                    except FileNotFoundError:
                        pass

    def prepare_environment(self, instances: dict[str, InstanceMetadata]) -> None:
        print("Copying team SSH public keys in the running instance(s)...")
        raw_instances = {
            key: inst.to_dict() for key, inst in instances.items()
        }
        add_ssh_keys_to_instances(raw_instances, self.config.ssh_config_file)
