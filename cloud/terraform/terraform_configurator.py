import os
import json
from pprint import pprint


class TerraformConfigurator:
    def __init__(self, cloud, ssh_key_path):
        self.cloud = cloud
        self.ssh_key_path = ssh_key_path

        self.main_tf = {'terraform': {'required_version': '>= 0.14.9'}}
        self.resources_tf = {'resource': {}}
        self.providers_tf = {'provider': {cloud: []}}

        if cloud == 'aws':
            self.resources_tf['resource']['aws_instance'] = {}
            self.resources_tf['resource']['aws_key_pair'] = {}
            self.main_tf['terraform']['required_providers'] = {
                'aws': {'source': 'hashicorp/aws', 'version': '~> 3.27'}
            }

    def configure_from_resources_json(self, resources_path):
        with open(resources_path) as f:
            resources_file = json.load(f)

        if resources_file['provider'] == 'aws':
            self.configure_aws_resources(resources_file)

    def configure_aws_resources(self, resource_file):
        for instance in resource_file['instances']:
            self.add_region_conf(instance['region'])
            self.add_instance_conf(instance)
            self.add_ssh_key_conf(instance['region'])

    def add_region_conf(self, region):
        # Do not create provider block if it already exists
        providers = [provider['alias'] for provider in self.providers_tf['provider'][self.cloud]]
        if region in providers:
            return

        if self.cloud == 'aws':
            self.__new_aws_provider(region)

    def __new_aws_provider(self, region):
        # If no profile was specified, select the default
        if not hasattr(self, 'aws_profile'):
            self.aws_profile = 'aws'

        new_provider = {
            'region': region,
            'alias': region,
            'profile': self.aws_profile,
        }

        self.providers_tf['provider'][self.cloud].append(new_provider)

    def add_instance_conf(self, instance):
        if self.cloud == 'aws':
            self.__new_aws_instance(instance)

    def __new_aws_instance(self, instance):
        if not instance['instance_type']:
            instance['instance_type'] = 't2.micro'

        name = instance['name'].replace('.', '-')

        # TODO: agree on a name for 'region' or 'location' across all cloud so we can move
        #      this code to 'add_instance_conf'
        aliases = [provider['alias'] for provider in self.providers_tf['provider'][self.cloud]]
        if instance['region'] not in aliases:
            print('Cannot add an instance if region provider is not set up')
            exit(1)

        new_instance = {
            'instance_type': instance['instance_type'],
            'ami': instance['ami'],
            'provider': f'aws.{instance["region"]}',
            'key_name': f'{instance["region"]}-key',
            'tags': {'name': name},
        }
        self.resources_tf['resource']['aws_instance'][name] = new_instance

    def add_ssh_key_conf(self, region):
        if self.cloud == 'aws':
            self.__new_aws_key_pair(region)

    def __new_aws_key_pair(self, region):
        key_name = f'{region}-key'
        
        new_key_pair = {
            'provider': f'aws.{region}',
            'key_name': key_name,
            'public_key': f'${{file(\"{self.ssh_key_path}.pub")}}',
        }

        self.resources_tf['resource']['aws_key_pair'][key_name] = new_key_pair

    def set_configuration(self):
        self.__dump_to_json(self.main_tf, 'main.tf.json')
        self.__dump_to_json(self.resources_tf, 'resources.tf.json')
        self.__dump_to_json(self.providers_tf, 'providers.tf.json')

    def __dump_to_json(self, content, file):
        with open(file, 'w') as config_file:
            json.dump(content, config_file)

    def print_configuration(self):
        pprint(self.resources_tf)
        pprint(self.providers_tf)

    def remove_configuration(self):
        for file in ['main.tf.json', 'resources.tf.json', 'providers.tf.json']:
            if os.path.exists(file):
                os.remove(file)

    def set_aws_profile(self, profile):
        self.aws_profile = profile
