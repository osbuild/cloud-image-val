from cloud.terraform.base_config_builder import BaseConfigBuilder


class AWSConfigBuilder(BaseConfigBuilder):
    cloud_name = 'aws'
    cloud_provider_definition = {'aws': {'source': 'hashicorp/aws', 'version': '~> 3.27'}}

    def build_providers(self):
        all_regions = self.__get_all_regions_from_resources_file()
        for region in all_regions:
            self.providers_tf['provider'][self.cloud_providers[self.cloud_name]]\
                .append(self.__new_aws_provider(region))

        return self.providers_tf

    def __get_all_regions_from_resources_file(self):
        instances_regions = [i['region'] for i in self.resources_dict['instances']]

        return list(dict.fromkeys(instances_regions))

    def __new_aws_provider(self, region):
        return {
            'region': region,
            'alias': region,
        }

    def build_resources(self):
        self.resources_tf['resource']['aws_key_pair'] = {}
        self.resources_tf['resource']['aws_instance'] = {}

        for instance in self.resources_dict['instances']:
            self.__new_aws_key_pair(instance)
            self.__new_aws_instance(instance)

        return self.resources_tf

    def __new_aws_key_pair(self, instance):
        region = instance['region']
        key_name = self.create_resource_name([instance['region'], 'key'])
        instance['aws_key_pair'] = key_name

        new_key_pair = {
            'provider': f'aws.{region}',
            'key_name': key_name,
            'public_key': f'${{file("{self.ssh_key_path}")}}'
        }
        self.add_tags(self.config, new_key_pair)

        self.resources_tf['resource']['aws_key_pair'][key_name] = new_key_pair

    def __new_aws_instance(self, instance):
        if not instance['instance_type']:
            # CIV will assume the AMI is x64. For ARM, the instance_type must be manually specified in resources.json
            instance['instance_type'] = 't3.large'

        name_tag = instance['name'].replace('.', '-')
        name = self.create_resource_name([name_tag])

        aliases = [provider['alias'] for provider in self.providers_tf['provider'][self.cloud_name]]
        if instance['region'] not in aliases:
            raise Exception('Cannot add an instance if region provider is not set up')

        new_instance = {
            'instance_type': instance['instance_type'],
            'ami': instance['ami'],
            'provider': f'aws.{instance["region"]}',
            'key_name': instance['aws_key_pair'],
            'tags': {'name': name_tag},
            'depends_on': [
                'aws_key_pair.{}'.format(instance['aws_key_pair'])
            ]
        }
        self.add_tags(self.config, new_instance)

        self.resources_tf['resource']['aws_instance'][name] = new_instance
