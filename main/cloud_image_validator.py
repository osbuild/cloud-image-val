import os
import time

from pprint import pprint
from cloud.terraform.terraform_controller import TerraformController
from cloud.terraform.terraform_configurator import TerraformConfigurator
from lib import ssh_lib
from test_suite.suite_runner import SuiteRunner


class CloudImageValidator:
    ssh_identity_file = '/tmp/ssh_key'
    ssh_pub_key_file = f'{ssh_identity_file}.pub'
    ssh_config_file = '/tmp/ssh_config'

    infra_controller = None
    infra_configurator = None

    def __init__(self,
                 resources_file,
                 output_file,
                 test_filter=None,
                 parallel=False,
                 debug=False):
        self.resources_file = resources_file
        self.output_file = output_file
        self.test_filter = test_filter
        self.parallel = parallel
        self.debug = debug

    def main(self):
        self.infra_controller = self.initialize_infrastructure()

        try:
            instances = self.deploy_infrastructure()

            self.run_tests_in_all_instances(instances)
        finally:
            self.cleanup()

    def initialize_infrastructure(self):
        ssh_lib.generate_ssh_key_pair(self.ssh_identity_file)

        self.infra_configurator = TerraformConfigurator(ssh_key_path=self.ssh_pub_key_file,
                                                        resources_path=self.resources_file)
        self.infra_configurator.configure_from_resources_json()

        if self.debug:
            self.infra_configurator.print_configuration()

        return TerraformController(self.infra_configurator)

    def deploy_infrastructure(self):
        self.infra_controller.create_infra()
        instances = self.infra_controller.get_instances()

        if self.debug:
            pprint(instances)

        ssh_lib.generate_instances_ssh_config(instances=instances,
                                              ssh_config_file=self.ssh_config_file,
                                              ssh_key_path=self.ssh_identity_file)

        return instances

    def run_tests_in_all_instances(self, instances):
        time.sleep(5)
        runner = SuiteRunner(cloud_provider=self.infra_configurator.cloud_name,
                             instances=instances,
                             ssh_config=self.ssh_config_file,
                             parallel=self.parallel,
                             debug=self.debug)
        runner.run_tests(self.output_file, self.test_filter)

    def cleanup(self):
        self.infra_controller.destroy_infra()

        os.remove(self.ssh_identity_file)
        os.remove(self.ssh_pub_key_file)

        if not self.debug:
            os.remove(self.ssh_config_file)
