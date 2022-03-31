import os
import json

from terraform_configurator import TerraformConfigurator


class TerraformController:
    def __init__(self, cloud):
        self.cloud = cloud

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
        output = os.popen('terraform show --json').read()
        json_output = json.loads(output)

        resources = json_output['values']['root_module']['resources_tf']

        instances_info = {}
        if self.cloud == 'aws':
            # 'address' corresponds to the tf resource id
            for resource in resources:
                instances_info[resource['address']] = {
                    'instance_id': resource['values']['id'],
                    'public_ip': resource['values']['public_ip'],
                    'public_dns': resource['values']['public_dns'],
                    'availability_zone': resource['values']['availability_zone'],
                    'ami': resource['values']['ami'],
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
    tf_conf = TerraformConfigurator('aws')
    tf_controller = TerraformController('aws')

    resources_test_file = os.path.join(os.path.dirname(__file__), 'sample/resources.json')
    tf_conf.configure_from_resources_json(resources_test_file)
    tf_conf.print_configuration()
    tf_conf.set_configuration()
    
    tf_controller.create_infra()
    print(tf_controller.get_instances())
    tf_controller.destroy_infra()
    tf_conf.remove_configuration()
