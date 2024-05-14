from cloud.opentofu.base_config_builder import BaseConfigBuilder


class AWSConfigBuilder(BaseConfigBuilder):
    cloud_name = 'aws'
    cloud_provider_definition = {'aws': {'source': 'hashicorp/aws', 'version': '~> 5.49.0'}}

    def build_providers(self):
        all_regions = self.__get_all_regions_from_resources_file()
        for region in all_regions:
            self.providers_tf['provider'][self.cloud_providers[self.cloud_name]] \
                .append(self.__new_aws_provider(region))

        return self.providers_tf

    def __get_all_regions_from_resources_file(self):
        instances_regions = [i['region'] for i in self.resources_dict['instances']]

        return list(dict.fromkeys(instances_regions))

    def __new_aws_provider(self, region):
        return {
            'region': region,
            'alias': region,
            'skip_region_validation': True
        }

    def build_resources(self):
        self.resources_tf['resource']['aws_key_pair'] = {}

        # Data needed to import custom networking/security resources if needed
        self.resources_tf['data'] = {}
        self.resources_tf['data']['aws_vpc'] = {}
        self.resources_tf['data']['aws_subnet'] = {}
        self.resources_tf['data']['aws_security_group'] = {}

        self.resources_tf['resource']['aws_instance'] = {}

        for instance in self.resources_dict['instances']:
            self.__new_aws_key_pair(instance)

            self.__get_data_aws_vpc(instance)
            self.__get_data_aws_subnet(instance)
            self.__get_data_aws_security_group(instance)

            self.__new_aws_instance(instance)

        # Cleanup data sources if they are empty
        data_sources_list = list(self.resources_tf['data'].keys())
        for source in data_sources_list:
            if not self.resources_tf['data'][source]:
                del self.resources_tf['data'][source]
        if not self.resources_tf['data']:
            del self.resources_tf['data']

        return self.resources_tf

    def __get_data_aws_vpc(self, instance):
        if 'custom_vpc_name' not in instance:
            return

        tf_data_type = 'aws_vpc'
        region = instance['region']
        vpc_name = self.create_resource_name([region, 'custom', 'vpc'])

        regional_resource_name = self.__get_tf_resource_name_by_region(tf_data_type, region, 'data')
        if regional_resource_name:
            instance[tf_data_type] = regional_resource_name
            return

        instance[tf_data_type] = vpc_name

        get_vpc = {
            'provider': f'aws.{region}',
            'filter': {
                'name': 'tag:Name',
                'values': [instance['custom_vpc_name']]
            }
        }

        self.resources_tf['data'][tf_data_type][vpc_name] = get_vpc

    def __get_data_aws_subnet(self, instance):
        if 'custom_subnet_name' not in instance:
            return

        tf_data_type = 'aws_subnet'
        region = instance['region']
        subnet_name = self.create_resource_name([region, 'custom', 'subnet'])

        regional_resource_name = self.__get_tf_resource_name_by_region(tf_data_type, region, 'data')
        if regional_resource_name:
            instance[tf_data_type] = regional_resource_name
            return

        instance[tf_data_type] = subnet_name

        aws_subnet = {
            'provider': f'aws.{region}',
            'filter': {
                'name': 'tag:Name',
                'values': [instance['custom_subnet_name']]
            }
        }

        self.resources_tf['data'][tf_data_type][subnet_name] = aws_subnet

    def __get_data_aws_security_group(self, instance):
        if 'custom_security_group_name' not in instance:
            return

        tf_data_type = 'aws_security_group'
        region = instance['region']
        security_group_name = self.create_resource_name([region, 'custom', 'security_group'])

        regional_resource_name = self.__get_tf_resource_name_by_region(tf_data_type, region, 'data')
        if regional_resource_name:
            instance[tf_data_type] = regional_resource_name
            return

        instance[tf_data_type] = security_group_name

        aws_subnets = {
            'provider': f'aws.{region}',
            'filter': {
                'name': 'tag:Name',
                'values': [instance['custom_security_group_name']]
            }
        }

        self.resources_tf['data'][tf_data_type][security_group_name] = aws_subnets

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
            instance['instance_type'] = 't3.medium'

        name_tag_value = instance['name'].replace('.', '-')
        name = self.create_resource_name([name_tag_value])

        aliases = [provider['alias'] for provider in self.providers_tf['provider'][self.cloud_name]]
        if instance['region'] not in aliases:
            raise Exception('Cannot add an instance if region provider is not set up')

        new_instance = {
            'instance_type': instance['instance_type'],
            'ami': instance['ami'],
            'provider': f'aws.{instance["region"]}',
            'key_name': instance['aws_key_pair'],
            'tags': {'name': name_tag_value},
            'depends_on': [
                'aws_key_pair.{}'.format(instance['aws_key_pair'])
            ]
        }

        if 'aws_subnet' in instance:
            declared_subnet_id = 'data.aws_subnet.{}.id'.format(instance['aws_subnet'])
            new_instance['subnet_id'] = f'${{{declared_subnet_id}}}'

        if 'aws_security_group' in instance:
            declared_security_group_id = 'data.aws_security_group.{}.id'.format(instance['aws_security_group'])
            new_instance['vpc_security_group_ids'] = [f'${{{declared_security_group_id}}}']

        self.add_tags(self.config, new_instance)

        self.resources_tf['resource']['aws_instance'][name] = new_instance

    def __get_tf_resource_name_by_region(self, resource_type, region, tf_definition_type='resource'):
        if resource_type in self.resources_tf[tf_definition_type]:
            for resource_name in self.resources_tf[tf_definition_type][resource_type].keys():
                if region in resource_name:
                    return resource_name

        return None
