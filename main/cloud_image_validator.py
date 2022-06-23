import json
import os

from pprint import pprint
from cloud.terraform.terraform_controller import TerraformController
from cloud.terraform.terraform_configurator import TerraformConfigurator
from lib import ssh_lib
from lib import console_lib
from test_suite.suite_runner import SuiteRunner


class CloudImageValidator:
    ssh_identity_file = '/tmp/ssh_key'
    ssh_pub_key_file = f'{ssh_identity_file}.pub'
    ssh_config_file = '/tmp/ssh_config'

    instances_json = '/tmp/instances.json'

    infra_configurator = None

    infra_controller = None

    def __init__(self,
                 resources_file,
                 output_file,
                 test_filter=None,
                 include_markers=None,
                 parallel=False,
                 debug=False,
                 stop_cleanup=False):
        self.resources_file = resources_file
        self.output_file = output_file

        self.test_filter = test_filter
        self.include_markers = include_markers

        self.parallel = parallel
        self.debug = debug
        self.stop_cleanup = stop_cleanup

    def main(self):
        self.infra_controller = self.initialize_infrastructure()
        exit_code = 0

        instances = None
        try:
            console_lib.print_divider('Deploying infrastructure')
            instances = self.deploy_infrastructure()

            console_lib.print_divider('Running tests')
            wait_status = self.run_tests_in_all_instances(instances)
            exit_code = wait_status >> 8

        except Exception as e:
            print(e)
            exit_code = 1

        finally:
            if self.stop_cleanup:
                self.print_ssh_commands_for_instances(instances)
                input('Press ENTER to proceed with cleanup:')

            console_lib.print_divider('Cleanup')
            self.cleanup()

            return exit_code

    def print_ssh_commands_for_instances(self, instances):
        if instances:
            for inst in instances.values():
                ssh_command = 'ssh -i {0} {1}@{2}'.format(self.ssh_identity_file,
                                                          inst['username'],
                                                          inst['public_dns'])
                instance_name = inst['name']
                print(f'{instance_name}:')
                print(f'\t{ssh_command}')

    def initialize_infrastructure(self):
        ssh_lib.generate_ssh_key_pair(self.ssh_identity_file)

        self.infra_configurator = TerraformConfigurator(ssh_key_path=self.ssh_pub_key_file,
                                                        resources_path=self.resources_file)
        self.infra_configurator.configure_from_resources_json()

        if self.debug:
            self.infra_configurator.print_configuration()

        return TerraformController(self.infra_configurator, self.debug)

    def deploy_infrastructure(self):
        self.infra_controller.create_infra()
        instances = self.infra_controller.get_instances()

        if self.debug:
            pprint(instances)

        self._write_instances_to_json(instances)

        ssh_lib.generate_instances_ssh_config(instances=instances,
                                              ssh_config_file=self.ssh_config_file,
                                              ssh_key_path=self.ssh_identity_file)

        return instances

    def _write_instances_to_json(self, instances):
        with open(self.instances_json, 'w') as file:
            json.dump(instances, file)

    def run_tests_in_all_instances(self, instances):
        runner = SuiteRunner(cloud_provider=self.infra_configurator.cloud_name,
                             instances=instances,
                             ssh_config=self.ssh_config_file,
                             parallel=self.parallel,
                             debug=self.debug)

        return runner.run_tests(self.output_file,
                                self.test_filter,
                                self.include_markers)

    def cleanup(self):
        self.infra_controller.destroy_infra()

        if not self.debug:
            os.remove(self.ssh_identity_file)
            os.remove(self.ssh_pub_key_file)
            os.remove(self.ssh_config_file)
            os.remove(self.instances_json)
