import json
import os
import traceback

from pprint import pprint
from cloud.opentofu.opentofu_controller import OpenTofuController
from cloud.opentofu.opentofu_configurator import OpenTofuConfigurator
from lib import ssh_lib
from lib import console_lib
from test_suite.suite_runner import SuiteRunner


class CloudImageValidator:
    infra_controller = None
    infra_configurator = None

    infra_error_exit_code = 100

    def __init__(self, config):
        self.config = config

    def main(self, attach=False):
        exit_code = 0
        instances = None

        try:
            if attach:
                console_lib.print_divider('Attaching to existing infrastructure...')
                self.infra_controller = self.attach_infrastructure()

                console_lib.print_divider('Attaching to existing instances...')
                instances = self.attach_instances()
            else:
                console_lib.print_divider('Initializing infrastructure')
                self.infra_controller = self.initialize_infrastructure()

                console_lib.print_divider('Deploying infrastructure')
                instances = self.deploy_infrastructure()

                console_lib.print_divider('Preparing environment')
                self.prepare_environment(instances)

            console_lib.print_divider('Running tests')
            wait_status = self.run_tests_in_all_instances(instances)

            exit_code = wait_status >> 8

        except Exception:
            traceback.print_exc()
            exit_code = self.infra_error_exit_code

        finally:
            if self.config['stop_cleanup']:
                if self.config['environment'] == 'local':
                    self.print_ssh_commands_for_instances(instances)
                    input('Press ENTER to proceed with cleanup:')
                elif self.config["environment"] == 'automated':
                    console_lib.print_divider('Skipping cleanup')
                    return exit_code
                else:
                    print('ERROR: --environment parameter should be either "local" or "automated"')
                    exit_code = self.infra_error_exit_code

            console_lib.print_divider('Cleanup')
            self.cleanup()

            return exit_code

    def print_ssh_commands_for_instances(self, instances):
        if instances:
            for inst in instances.values():
                ssh_command = 'ssh -i {0} {1}@{2}'.format(self.config['ssh_identity_file'],
                                                          inst['username'],
                                                          inst['address'])
                instance_name = inst['name']
                print(f'{instance_name}:')
                print(f'\t{ssh_command}')

    def attach_infrastructure(self):
        self.infra_configurator = OpenTofuConfigurator(ssh_key_path=self.config['ssh_pub_key_file'],
                                                       resources_path=self.config['resources_file'],
                                                       config=self.config)

        return OpenTofuController(self.infra_configurator, self.config['debug'])

    def attach_instances(self):
        return self.infra_controller.get_instances()

    def initialize_infrastructure(self):
        ssh_lib.generate_ssh_key_pair(self.config['ssh_identity_file'])

        self.infra_configurator = OpenTofuConfigurator(ssh_key_path=self.config['ssh_pub_key_file'],
                                                       resources_path=self.config['resources_file'],
                                                       config=self.config)
        self.infra_configurator.configure_from_resources_json()

        if self.config['debug']:
            self.infra_configurator.print_configuration()

        return OpenTofuController(self.infra_configurator, self.config['debug'])

    def deploy_infrastructure(self):
        self.infra_controller.create_infra()
        instances = self.infra_controller.get_instances()

        if self.config['debug']:
            pprint(instances)

        self._write_instances_to_json(instances)

        ssh_lib.generate_instances_ssh_config(instances=instances,
                                              ssh_config_file=self.config['ssh_config_file'],
                                              ssh_key_path=self.config['ssh_identity_file'])

        return instances

    def _write_instances_to_json(self, instances):
        with open(self.config['instances_json'], 'w') as file:
            json.dump(instances, file, indent=4)

    def prepare_environment(self, instances):
        print('Copying team SSH public keys in the running instance(s)...')
        ssh_lib.add_ssh_keys_to_instances(instances, self.config['ssh_config_file'])

    def run_tests_in_all_instances(self, instances):
        runner = SuiteRunner(cloud_provider=self.infra_configurator.cloud_name,
                             instances=instances,
                             ssh_config=self.config['ssh_config_file'],
                             parallel=self.config['parallel'],
                             debug=self.config['debug'])

        return runner.run_tests(self.config['test_suites'],
                                self.config['output_file'],
                                self.config['test_filter'],
                                self.config['include_markers'])

    def cleanup(self):
        self.infra_controller.destroy_infra()

        if not self.config['debug']:
            os.remove(self.config['ssh_identity_file'])
            os.remove(self.config['ssh_pub_key_file'])
            os.remove(self.config['ssh_config_file'])
            os.remove(self.config['instances_json'])
