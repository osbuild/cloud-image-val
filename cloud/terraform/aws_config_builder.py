from cloud.terraform.base_config_builder import BaseConfigBuilder


class AWSConfigBuilder(BaseConfigBuilder):
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

        if 'package-testing' in self.config['tags']:
            self.resources_tf['resource']['aws_vpc'] = {}
            self.resources_tf['resource']['aws_security_group'] = {}
            self.resources_tf['resource']['aws_vpc_security_group_ingress_rule'] = {}
            self.resources_tf['resource']['aws_vpc_security_group_egress_rule'] = {}
            self.resources_tf['resource']['aws_subnet'] = {}
            self.resources_tf['resource']['aws_efs_file_system'] = {}
            self.resources_tf['resource']['aws_efs_mount_target'] = {}

        self.resources_tf['resource']['aws_instance'] = {}

        for instance in self.resources_dict['instances']:
            self.__new_aws_key_pair(instance)

            if 'package-testing' in self.config['tags']:
                self.__new_aws_vpc(instance)
                self.__new_aws_security_group(instance)
                self.__new_aws_vpc_security_group_ingress_rule(instance)
                self.__new_aws_vpc_security_group_egress_rule(instance)
                self.__new_aws_subnet(instance)
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

    def __new_aws_vpc(self, instance):
        tf_resource_type = 'aws_vpc'
        region = instance['region']
        vpc_name = self.create_resource_name([region, 'vpc'])

        if self.__test_resource_exists_in_region(tf_resource_type, region):
            instance[tf_resource_type] = vpc_name
            return

        instance[tf_resource_type] = vpc_name

        new_vpc = {
            'cidr_block': '10.0.0.0/16'
        }

        self.add_tags(self.config, new_vpc)

        self.resources_tf['resource'][tf_resource_type][vpc_name] = new_vpc

    def __new_aws_security_group(self, instance):
        tf_resource_type = 'aws_security_group'
        region = instance['region']
        security_group_name = self.create_resource_name([region, 'security-group'])

        if self.__test_resource_exists_in_region(tf_resource_type, region):
            instance[tf_resource_type] = security_group_name
            return

        instance[tf_resource_type] = security_group_name

        declared_vpc_id = 'aws_vpc.{}.id'.format(instance['aws_vpc'])

        new_security_group = {
            'name': security_group_name,
            'vpc_id': f'${{{declared_vpc_id}}}'
        }

        self.add_tags(self.config, new_security_group)

        self.resources_tf['resource'][tf_resource_type][security_group_name] = new_security_group

    def __new_aws_vpc_security_group_ingress_rule(self, instance):
        tf_resource_type = 'aws_vpc_security_group_ingress_rule'
        region = instance['region']
        ingress_rule_name = self.create_resource_name([region, 'vpc', 'ingress-rule'])

        if self.__test_resource_exists_in_region(tf_resource_type, region):
            instance[tf_resource_type] = ingress_rule_name
            return

        instance[tf_resource_type] = ingress_rule_name

        declared_security_group_id = 'aws_security_group.{}.id'.format(instance['aws_security_group'])

        new_ingress_rule = {
            'from_port': 0,
            'to_port': 0,
            'ip_protocol': -1,
            'cidr_ipv4': '0.0.0.0/0',
            'security_group_id': f'${{{declared_security_group_id}}}'
        }

        self.add_tags(self.config, new_ingress_rule)

        self.resources_tf['resource'][tf_resource_type][ingress_rule_name] = new_ingress_rule

    def __new_aws_vpc_security_group_egress_rule(self, instance):
        tf_resource_type = 'aws_vpc_security_group_egress_rule'
        region = instance['region']
        egress_rule_name = self.create_resource_name([region, 'vpc', 'ingress-rule'])

        if self.__test_resource_exists_in_region(tf_resource_type, region):
            instance[tf_resource_type] = egress_rule_name
            return

        instance[tf_resource_type] = egress_rule_name

        declared_security_group_id = 'aws_security_group.{}.id'.format(instance['aws_security_group'])

        new_egress_rule = {
            'from_port': 0,
            'to_port': 0,
            'ip_protocol': -1,
            'cidr_ipv4': '0.0.0.0/0',
            'security_group_id': f'${{{declared_security_group_id}}}'
        }

        self.add_tags(self.config, new_egress_rule)

        self.resources_tf['resource'][tf_resource_type][egress_rule_name] = new_egress_rule

    def __new_aws_subnet(self, instance):
        tf_resource_type = 'aws_subnet'
        region = instance['region']
        subnet_name = self.create_resource_name([region, 'subnet'])

        if self.__test_resource_exists_in_region(tf_resource_type, region):
            instance[tf_resource_type] = subnet_name
            return

        instance[tf_resource_type] = subnet_name

        declared_vpc_id = 'aws_vpc.{}.id'.format(instance['aws_vpc'])

        new_subnet = {
            'vpc_id': f'${{{declared_vpc_id}}}',
            'cidr_block': '10.0.0.0/16'
        }

        self.add_tags(self.config, new_subnet)

        self.resources_tf['resource'][tf_resource_type][subnet_name] = new_subnet

    def __new_aws_efs_file_system(self, instance):
        tf_resource_type = 'aws_efs_file_system'
        region = instance['region']
        efs_filesystem_name = self.create_resource_name([region, 'efs', 'filesystem'])

        if self.__test_resource_exists_in_region(tf_resource_type, region):
            instance[tf_resource_type] = efs_filesystem_name
            return

        instance[tf_resource_type] = efs_filesystem_name

        new_efs_filesystem = {
            'creation_token': efs_filesystem_name
        }

        self.add_tags(self.config, new_efs_filesystem)

        self.resources_tf['resource'][tf_resource_type][efs_filesystem_name] = new_efs_filesystem

    def __new_aws_efs_mount_target(self, instance):
        tf_resource_type = 'aws_efs_mount_target'
        region = instance['region']
        efs_mount_target_name = self.create_resource_name([region, 'efs', 'mount-target'])

        if self.__test_resource_exists_in_region(tf_resource_type, region):
            instance[tf_resource_type] = efs_mount_target_name
            return

        instance[tf_resource_type] = efs_mount_target_name

        declared_filesystem_id = 'aws_efs_file_system.{}.id'.format(instance['aws_efs_file_system'])
        declared_subnet_id = 'aws_subnet.{}.id'.format(instance['aws_subnet'])
        declared_security_group_id = 'aws_security_group.{}.id'.format(instance['aws_security_group'])

        new_efs_mount_target = {
            'file_system_id': f'${{{declared_filesystem_id}}}',
            'subnet_id': f'${{{declared_subnet_id}}}',
            'security_groups': [f'${{{declared_security_group_id}}}']
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

        if 'aws_security_group' in instance:
            # declared_security_group_id = 'aws_security_group.{}.id'.format(instance['aws_security_group'])
            # new_instance['security_groups'] = [f'${{{declared_security_group_id}}}']
            print(f'Found {instance["aws_security_group"]} security group for instance {instance["name"]}')

        self.add_tags(self.config, new_instance)

        self.resources_tf['resource']['aws_instance'][name] = new_instance

    def __test_resource_exists_in_region(self, resource_type, region):
        if resource_type in self.resources_tf['resource']:
            for resource_name in self.resources_tf['resource'][resource_type].keys():
                if region in resource_name:
                    return True

        return False
