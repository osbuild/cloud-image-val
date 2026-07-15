from cloud.opentofu.base_config_builder import BaseConfigBuilder


class OCIConfigBuilder(BaseConfigBuilder):
    cloud_name = 'oci'
    cloud_provider_definition = {'oci': {'source': 'oracle/oci', 'version': '~> 8.16'}}
    resource_tags_key = 'freeform_tags'

    def build_providers(self):
        all_regions = self.__get_all_regions_from_resources_file()
        for region in all_regions:
            self.providers_tf['provider'][self.cloud_providers[self.cloud_name]] \
                .append(self.__new_oci_provider(region))

        return self.providers_tf

    def __get_all_regions_from_resources_file(self):
        regions = [i['region'] for i in self.resources_dict['instances']]
        return list(dict.fromkeys(regions))

    def __new_oci_provider(self, region):
        return {
            'config_file_profile': self.resources_dict.get('profile', 'DEFAULT'),
            'region': region,
            'alias': region,
        }

    def build_resources(self):
        self.resources_tf['data'] = {}
        self.resources_tf['data']['oci_identity_availability_domains'] = {}
        self.resources_tf['resource']['oci_core_vcn'] = {}
        self.resources_tf['resource']['oci_core_internet_gateway'] = {}
        self.resources_tf['resource']['oci_core_default_route_table'] = {}
        self.resources_tf['resource']['oci_core_subnet'] = {}
        self.resources_tf['resource']['oci_core_instance'] = {}

        for instance in self.resources_dict['instances']:
            self.__new_oci_network(instance)
            self.__new_oci_instance(instance)

        return self.resources_tf

    def __new_oci_network(self, instance):
        region = instance['region']
        compartment_id = instance['compartment_id']

        # Availability domains data source (one per region)
        ads_name = self.create_resource_name([region, 'ads'])
        if not self.__get_tf_resource_name_by_region(
                'oci_identity_availability_domains', region, 'data'):
            self.resources_tf['data']['oci_identity_availability_domains'][ads_name] = {
                'provider': f'oci.{region}',
                'compartment_id': compartment_id,
            }
        else:
            ads_name = self.__get_tf_resource_name_by_region(
                'oci_identity_availability_domains', region, 'data')
        instance['ads'] = ads_name

        # VCN (one per region)
        vcn_name = self.create_resource_name([region, 'vcn'])
        if not self.__get_tf_resource_name_by_region('oci_core_vcn', region):
            self.resources_tf['resource']['oci_core_vcn'][vcn_name] = {
                'provider': f'oci.{region}',
                'compartment_id': compartment_id,
                'cidr_blocks': ['10.0.0.0/16'],
                'display_name': vcn_name,
                'dns_label': 'civvcn',
            }
        else:
            vcn_name = self.__get_tf_resource_name_by_region('oci_core_vcn', region)
        instance['vcn'] = vcn_name

        # Internet Gateway (one per region)
        ig_name = self.create_resource_name([region, 'ig'])
        if not self.__get_tf_resource_name_by_region('oci_core_internet_gateway', region):
            declared_vcn_id = f'oci_core_vcn.{vcn_name}.id'
            self.resources_tf['resource']['oci_core_internet_gateway'][ig_name] = {
                'provider': f'oci.{region}',
                'compartment_id': compartment_id,
                'vcn_id': f'${{{declared_vcn_id}}}',
                'display_name': ig_name,
            }
        else:
            ig_name = self.__get_tf_resource_name_by_region('oci_core_internet_gateway', region)
        instance['ig'] = ig_name

        # Default route table (one per region)
        rt_name = self.create_resource_name([region, 'rt'])
        if not self.__get_tf_resource_name_by_region('oci_core_default_route_table', region):
            declared_default_rt_id = f'oci_core_vcn.{vcn_name}.default_route_table_id'
            declared_ig_id = f'oci_core_internet_gateway.{ig_name}.id'
            self.resources_tf['resource']['oci_core_default_route_table'][rt_name] = {
                'provider': f'oci.{region}',
                'manage_default_resource_id': f'${{{declared_default_rt_id}}}',
                'route_rules': {
                    'network_entity_id': f'${{{declared_ig_id}}}',
                    'destination': '0.0.0.0/0',
                    'destination_type': 'CIDR_BLOCK',
                },
            }
        else:
            rt_name = self.__get_tf_resource_name_by_region('oci_core_default_route_table', region)
        instance['rt'] = rt_name

        # Subnet (one per region)
        subnet_name = self.create_resource_name([region, 'subnet'])
        if not self.__get_tf_resource_name_by_region('oci_core_subnet', region):
            declared_vcn_id = f'oci_core_vcn.{vcn_name}.id'
            declared_default_rt_id = f'oci_core_vcn.{vcn_name}.default_route_table_id'
            self.resources_tf['resource']['oci_core_subnet'][subnet_name] = {
                'provider': f'oci.{region}',
                'compartment_id': compartment_id,
                'vcn_id': f'${{{declared_vcn_id}}}',
                'cidr_block': '10.0.1.0/24',
                'display_name': subnet_name,
                'dns_label': 'civsubnet',
                'route_table_id': f'${{{declared_default_rt_id}}}',
            }
        else:
            subnet_name = self.__get_tf_resource_name_by_region('oci_core_subnet', region)
        instance['subnet'] = subnet_name

    def __new_oci_instance(self, instance):
        region = instance['region']
        name_value = instance['name'].replace('.', '-')
        name = self.create_resource_name([name_value])

        declared_ad = (
            f'data.oci_identity_availability_domains'
            f'.{instance["ads"]}.availability_domains[0].name'
        )
        declared_subnet_id = f'oci_core_subnet.{instance["subnet"]}.id'

        new_instance = {
            'provider': f'oci.{region}',
            'availability_domain': f'${{{declared_ad}}}',
            'compartment_id': instance['compartment_id'],
            'display_name': name_value,
            'shape': instance.get('shape', 'VM.Standard.E4.Flex'),
            'source_details': {
                'source_type': 'image',
                'source_id': instance['image_id'],
            },
            'create_vnic_details': {
                'subnet_id': f'${{{declared_subnet_id}}}',
                'assign_public_ip': True,
            },
            'metadata': {
                'ssh_authorized_keys': f'${{file("{self.ssh_key_path}")}}'
            },
            'depends_on': [f'oci_core_subnet.{instance["subnet"]}'],
        }

        if '.Flex' in new_instance['shape']:
            new_instance['shape_config'] = {
                'ocpus': instance.get('ocpus', 2),
                'memory_in_gbs': instance.get('memory_in_gbs', 16),
            }

        self.add_tags(self.config, new_instance)

        self.resources_tf['resource']['oci_core_instance'][name] = new_instance

    def __get_tf_resource_name_by_region(self, resource_type, region, tf_definition_type='resource'):
        if resource_type in self.resources_tf[tf_definition_type]:
            for resource_name in self.resources_tf[tf_definition_type][resource_type].keys():
                if region in resource_name:
                    return resource_name
        return None
