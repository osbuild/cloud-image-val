from ast import alias
import os
import json
import sys
from pprint import pprint


class TerraformConfigurator:
    def __init__(self, cloud):
        self.cloud = cloud

        # Change cwd to file path
        os.chdir(sys.path[0])

        if cloud == 'aws':
            self.cloud_instance = 'aws_instance'
        self.resources = {'resource': {self.cloud_instance: {}}}
        self.providers = {'provider': {cloud: []}}

    def __dump_to_json(self, content, file):
        with open(file, 'w') as config_file:
            json.dump(content, config_file)

    def set_aws_profile(self, profile):
        self.aws_profile = profile

    def add_region_conf(self, region):
        # Do not create provider block if it already exists
        providers = [provider['alias'] for provider in self.providers['provider'][self.cloud]]
        if region in providers:
            return

        if self.cloud == 'aws':
            new_provider = self.__new_aws_provider(region)

    def __new_aws_provider(self, region):
        # If no profile was specified, select the default
        if not hasattr(self, 'aws_profile'):
            self.aws_profile = 'aws'

        new_provider = {
            'region': region,
            'alias': region,
            'profile': self.aws_profile,
        }

        self.providers['provider'][self.cloud].append(new_provider)

    def add_instance_conf(self, instance):
        if self.cloud == 'aws':
            self.__new_aws_instance(instance)

    def __new_aws_instance(self, instance):
        if not instance['instance_type']:
            instance['instance_type'] = 't2.micro'

        name = instance['name'].replace('.', '-')

        # TODO: agree on a name for 'region' or 'location' across all cloud so we can move
        #      this code to 'add_instance_conf'
        aliases = [provider['alias'] for provider in self.providers['provider'][self.cloud]]
        if instance['region'] not in aliases:
            print('Cannot add an instance if region provider is not set up')
            exit(1)

        new_instance = {
            'instance_type': instance['instance_type'],
            'ami': instance['ami'],
            'provider': f'aws.{instance["region"]}',
            'tags': {'name': name},
        }
        self.resources['resource']['aws_instance'][name] = new_instance

    def print_configuration(self):
        pprint(self.resources)
        pprint(self.providers)

    def set_configuration(self):
        main_tf = {
            'terraform': {
                'required_providers': {'aws': {'source': 'hashicorp/aws', 'version': '~> 3.27'}},
                'required_version': '>= 0.14.9',
            }
        }
        self.__dump_to_json(main_tf, 'main.tf.json')
        self.__dump_to_json(self.resources, 'resources.tf.json')
        self.__dump_to_json(self.providers, 'providers.tf.json')

    def remove_conf(self):
        for file in ['providers.tf', 'resources.tf']:
            if os.path.exists(file):
                os.remove(file)

    def configure_from_resources_json(self, resources_path):
        with open(resources_path) as f:
            resources_file = json.load(f)

        if resources_file['provider'] == 'aws':
            self.configure_aws_resources(resources_file)

    def configure_aws_resources(self, resource_file):
        for instance in resource_file['instances']:
            self.add_region_conf(instance['region'])
            self.add_instance_conf(instance)


class TerraformController:
    def __init__(self, cloud):
        self.cloud = cloud

        # Change cwd to file path
        os.chdir(sys.path[0])

    def get_instances(self):
        output = os.popen('terraform show --json').read()
        json_output = json.loads(output)

        resources = json_output['values']['root_module']['resources']

        if self.cloud == 'aws':

            instances_info = {}
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

    def create_infra(self):
        cmd_output = os.system('terraform init')
        if cmd_output:
            print('terraform init command failed, check configuration')
            exit(1)

        cmd_output = os.system('terraform apply -auto-approve')
        if cmd_output:
            print('terraform apply command failed, check configuration')
            exit(1)

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

    tf_conf.configure_from_resources_json('sample/resources.json')
    tf_conf.print_configuration()
    tf_conf.set_configuration()
    tf_controller.create_infra()
    print(tf_controller.get_instances())
    tf_controller.destroy_infra()
    tf_conf.remove_conf()
