import os
import json

from cloud.terraform.terraform_configurator import TerraformConfigurator


class TerraformController:
    def __init__(self, tf_configurator):
        self.cloud = tf_configurator.cloud
        self.tf_configurator = tf_configurator

    def create_infra(self):
        cmd_output = os.system('terraform init')
        if cmd_output:
            print('terraform init command failed, check configuration')
            exit(1)

        cmd_output = os.system('terraform apply -auto-approve')
        if cmd_output:
            print('terraform apply command failed, check configuration')
            exit(1)

    def get_instances(self):
        output = os.popen('terraform show --json')
        output = output.read()
        print(output)
        json_output = json.loads(output)

        resources = json_output['values']['root_module']['resources']

        if self.cloud == 'aws':
            instances_info = self.get_instances_aws(resources)

        return instances_info

    def get_instances_aws(self, resources):
        instances_info = {}

        # 'address' key corresponds to the tf resource id
        for resource in resources:
            if 'aws_instance' not in resource['address']:
                continue

            username = self.tf_configurator.get_username_by_instance_name(
                resource['address'].split('.')[1]
            )
            
            instances_info[resource['address']] = {
                'instance_id': resource['values']['id'],
                'public_ip': resource['values']['public_ip'],
                'public_dns': resource['values']['public_dns'],
                'availability_zone': resource['values']['availability_zone'],
                'ami': resource['values']['ami'],
                'username': username,
            }

        return instances_info           

    def destroy_resource(self, resource_id):
        cmd_output = os.system(f'terraform destroy -target={resource_id}')
        if cmd_output:
            print('terraform destroy specific resource command failed')
            exit(1)

    def destroy_infra(self):
        cmd_output = os.system('terraform destroy -auto-approve')
        if cmd_output:
            print('terraform destroy command failed')
            exit(1)


if __name__ == '__main__':
    resources_test_file = os.path.join(os.path.dirname(__file__), 'sample/resources.json')

    tf_conf = TerraformConfigurator('/tmp/test-key.pub', resources_test_file)
    tf_controller = TerraformController(tf_conf)

    try:
        tf_conf.configure_from_resources_json()
        tf_conf.print_configuration()
        tf_conf.set_configuration()

        tf_controller.create_infra()
        print(tf_controller.get_instances())
        input("Test instances access via ssh. Press ENTER to remove infra")

    finally:
        tf_controller.destroy_infra()
        tf_conf.remove_configuration()
