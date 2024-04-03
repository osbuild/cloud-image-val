from cloud.opentofu.base_config_builder import BaseConfigBuilder


class AWSConfigBuilderEfs(BaseConfigBuilder):
    cloud_name = 'aws'
    cloud_provider_definition = {'aws': {'source': 'hashicorp/aws', 'version': '~> 4.62.0'}}

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

        # Resources needed for efs creation
        self.resources_tf['data'] = {}
        self.resources_tf['data']['aws_vpc'] = {}
        self.resources_tf['data']['aws_subnets'] = {}
        self.resources_tf['resource']['aws_efs_file_system'] = {}
        self.resources_tf['resource']['aws_efs_mount_target'] = {}

        self.resources_tf['resource']['aws_instance'] = {}

        for instance in self.resources_dict['instances']:
            self.__new_aws_key_pair(instance)

            self.__get_data_aws_vpc(instance)
            self.__get_data_aws_subnets(instance)
            self.__new_aws_efs_file_system(instance)
            self.__new_aws_efs_mount_target(instance)

            self.__new_aws_instance(instance)

        return self.resources_tf

    def __new_aws_key_pair(self, instance):
        region = instance['region']
        key_name = self.create_resource_name([region, 'key'])
        instance['aws_key_pair'] = key_name

        new_key_pair = {
            'provider': f'aws.{region}',
            'key_name': key_name,
            'public_key': f'${{file("{self.ssh_key_path}")}}'
        }
        self.add_tags(self.config, new_key_pair)

        self.resources_tf['resource']['aws_key_pair'][key_name] = new_key_pair

    def __get_data_aws_vpc(self, instance):
        tf_data_type = 'aws_vpc'
        region = instance['region']
        vpc_name = self.create_resource_name([region, 'default', 'vpc'])

        regional_resource_name = self.__get_tf_resource_name_by_region(tf_data_type, region, 'data')
        if regional_resource_name:
            instance[tf_data_type] = regional_resource_name
            return

        instance[tf_data_type] = vpc_name

        get_vpc = {
            'provider': f'aws.{region}',
            'default': True
        }

        self.resources_tf['data'][tf_data_type][vpc_name] = get_vpc

    def __get_data_aws_subnets(self, instance):
        tf_data_type = 'aws_subnets'
        region = instance['region']
        all_subnets_name = self.create_resource_name([region, 'all', 'subnets'])

        regional_resource_name = self.__get_tf_resource_name_by_region(tf_data_type, region, 'data')
        if regional_resource_name:
            instance[tf_data_type] = regional_resource_name
            return

        instance[tf_data_type] = all_subnets_name

        declared_vpc_id = 'data.aws_vpc.{}.id'.format(instance['aws_vpc'])

        aws_subnets = {
            'provider': f'aws.{region}',
            'filter': {
                'name': 'vpc-id',
                'values': [f'${{{declared_vpc_id}}}']
            }
        }

        self.resources_tf['data'][tf_data_type][all_subnets_name] = aws_subnets

    def __new_aws_efs_file_system(self, instance):
        tf_resource_type = 'aws_efs_file_system'
        region = instance['region']
        efs_filesystem_name = self.create_resource_name([region, 'efs', 'filesystem'])

        regional_resource_name = self.__get_tf_resource_name_by_region(tf_resource_type, region)
        if regional_resource_name:
            instance[tf_resource_type] = regional_resource_name
            return

        instance[tf_resource_type] = efs_filesystem_name

        new_efs_filesystem = {
            'provider': f'aws.{region}',
            'creation_token': efs_filesystem_name,
            'encrypted': 'true',
            'tags': {'name': efs_filesystem_name}
        }

        self.add_tags(self.config, new_efs_filesystem)

        self.resources_tf['resource'][tf_resource_type][efs_filesystem_name] = new_efs_filesystem

    def __new_aws_efs_mount_target(self, instance):
        tf_resource_type = 'aws_efs_mount_target'
        region = instance['region']
        efs_mount_target_name = self.create_resource_name([region, 'efs', 'mount-target'])

        regional_resource_name = self.__get_tf_resource_name_by_region(tf_resource_type, region)
        if regional_resource_name:
            instance[tf_resource_type] = regional_resource_name
            return

        instance[tf_resource_type] = efs_mount_target_name

        declared_aws_subnets = 'data.aws_subnets.{}.ids'.format(instance['aws_subnets'])
        declared_filesystem_id = 'aws_efs_file_system.{}.id'.format(instance['aws_efs_file_system'])

        new_efs_mount_target = {
            'provider': f'aws.{region}',
            'for_each': f'${{toset({declared_aws_subnets})}}',
            'file_system_id': f'${{{declared_filesystem_id}}}',
            'subnet_id': '${each.value}',
        }

        self.resources_tf['resource'][tf_resource_type][efs_mount_target_name] = new_efs_mount_target

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

        self.add_tags(self.config, new_instance)

        self.resources_tf['resource']['aws_instance'][name] = new_instance

    def __get_tf_resource_name_by_region(self, resource_type, region, tf_definition_type='resource'):
        if resource_type in self.resources_tf[tf_definition_type]:
            for resource_name in self.resources_tf[tf_definition_type][resource_type].keys():
                if region in resource_name:
                    return resource_name

        return None
