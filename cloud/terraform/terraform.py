from ast import alias
import os
import json


class TerraformConfigurator:
    def __init__(self, cloud):
        self.cloud = cloud

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
        if self.cloud == 'aws':
            new_provider = self.__new_aws_provider(region)

        self.providers['provider'][self.cloud].append(new_provider)

    def __new_aws_provider(self, region):
        # If no profile was specified, select the default
        if not hasattr(self, 'aws_profile'):
            self.aws_profile = 'aws'

        new_provider = {
            'region': region,
            'alias': region,
            'profile': self.aws_profile,
        }

        return new_provider

    def add_instance_conf(self, region, image_id, instance_type=''):
        aliases = [provider['alias'] for provider in self.providers['provider'][self.cloud]]
        if region not in aliases:
            print('Cannot add an instance if region provider is not set up')
            exit(1)

        if self.cloud == 'aws':
            instance_name = self.__new_aws_instance(region, image_id, instance_type)
        
        return instance_name

    def __new_aws_instance(self, region, image_id, instance_type):
            if not instance_type:
                instance_type = 't2.micro'

            instance_name = f'{region}-{instance_type}'.replace('.', '-')
            new_instance = {
                'instance_type': instance_type,
                'ami': image_id,
                'provider': f'aws.{region}',
                'tags': {'name': instance_name},
            }
            self.resources['resource']['aws_instance'][instance_name] = new_instance

    def set_configuration(self):
        self.__dump_to_json(self.resources, 'resources.tf.json')
        self.__dump_to_json(self.providers, 'providers.tf.json')

    def remove_conf(self):
        for file in ['providers.tf','resources.tf']:
            if os.path.exists(file):
                os.remove(file)


class TerraformerController:
    def __init__(self, cloud):
        self.cloud = cloud

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

        cmd_output = os.system('terraform apply')
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
    tf_controller = TerraformerController('aws')

    tf_conf.add_region_conf('us-east-1')
    tf_conf.add_instance_conf('us-east-1', 'ami-0767af0854a146e3e')
    tf_conf.set_configuration()
    tf_controller.create_infra()
    print(tf_controller.get_instances())
    tf_controller.destroy_infra()
    tf_conf.remove_conf()
