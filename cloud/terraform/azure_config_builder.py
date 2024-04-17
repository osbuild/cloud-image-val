from cloud.terraform.base_config_builder import BaseConfigBuilder


class AzureConfigBuilder(BaseConfigBuilder):
    cloud_name = 'azure'
    cloud_provider_definition = {'azurerm': {'source': 'hashicorp/azurerm', 'version': '~> 3.51.0'}}

    default_vm_size = 'Standard_DS1_v2'
    default_admin_username = 'azure'
    default_location = 'eastus'

    def __init__(self, resources_dict, ssh_key_path, config):
        super().__init__(resources_dict, ssh_key_path, config)

        self.subscription_id = resources_dict['subscription_id']
        self.resource_group = resources_dict['resource_group']

        self.azure_resource_id_base = f'/subscriptions/{self.subscription_id}/resourceGroups/' \
                                      f'{self.resource_group}/providers'

    def build_providers(self):
        self.providers_tf['provider'][self.cloud_providers[self.cloud_name]] \
            .append(self.__new_azure_provider())

        return self.providers_tf

    def __new_azure_provider(self):
        return {
            'subscription_id': self.subscription_id,
            'features': {},
            'skip_provider_registration': True,
        }

    def build_resources(self):
        self.resources_tf['resource']['azurerm_virtual_network'] = {}
        self.resources_tf['resource']['azurerm_subnet'] = {}

        # VM specific resources
        self.resources_tf['resource']['azurerm_image'] = {}
        self.resources_tf['resource']['azurerm_public_ip'] = {}
        self.resources_tf['resource']['azurerm_network_interface'] = {}
        self.resources_tf['resource']['azurerm_linux_virtual_machine'] = {}

        for instance in self.resources_dict['instances']:
            instance['hostname'] = self.create_resource_name(['vm'])

            if 'location' in instance:
                instance['location'] = instance['location'].lower().replace(' ', '')
            else:
                instance['location'] = self.default_location

            self.__new_azure_virtual_network(instance)
            self.__new_azure_subnet(instance)

            if 'vhd_uri' in instance:
                self.__new_azure_image(instance)

            self.__new_azure_public_ip(instance)
            self.__new_azure_nic(instance)
            self.__new_azure_vm(instance)

        if not self.resources_tf['resource']['azurerm_image']:
            del self.resources_tf['resource']['azurerm_image']

        return self.resources_tf

    def __new_azure_image(self, instance):
        name = self.create_resource_name([instance['location'], 'image'])

        instance['image_from_vhd'] = name

        os_disk = {
            'os_type': 'Linux',
            'os_state': 'Generalized',
            'blob_uri': instance['vhd_uri']
        }

        new_image = {
            'name': name,
            'location': instance['location'],
            'resource_group_name': self.resource_group,
            'os_disk': os_disk
        }
        self.add_tags(self.config, new_image)

        self.resources_tf['resource']['azurerm_image'][name] = new_image

    def __new_azure_virtual_network(self, instance):
        name = self.create_resource_name([instance['location'], 'network'])
        instance['azurerm_virtual_network'] = name

        new_virtual_network = {
            'name': name,
            'address_space': ['10.0.0.0/16'],
            'location': instance['location'],
            'resource_group_name': self.resource_group
        }
        self.add_tags(self.config, new_virtual_network)

        self.resources_tf['resource']['azurerm_virtual_network'][name] = new_virtual_network

    def __new_azure_subnet(self, instance):
        name = self.create_resource_name([instance['location'], 'subnet'])
        instance['azurerm_subnet'] = name

        new_subnet = {
            'name': name,
            'resource_group_name': self.resource_group,
            'virtual_network_name': instance['azurerm_virtual_network'],
            'address_prefixes': ['10.0.2.0/24'],
            'depends_on': [
                'azurerm_virtual_network.{}'.format(instance['azurerm_virtual_network']),
            ]
        }

        self.resources_tf['resource']['azurerm_subnet'][name] = new_subnet

    def __new_azure_public_ip(self, instance):
        name = self.create_resource_name([instance['hostname'], 'public-ip'])
        instance['azurerm_public_ip'] = name

        new_public_ip = {
            'name': name,
            'resource_group_name': self.resource_group,
            'location': instance['location'],
            'allocation_method': 'Static',
            'domain_name_label': instance['hostname']
        }
        self.add_tags(self.config, new_public_ip)

        self.resources_tf['resource']['azurerm_public_ip'][name] = new_public_ip

    def __new_azure_nic(self, instance):
        name = self.create_resource_name([instance['hostname'], 'nic'])
        instance['azurerm_network_interface'] = name

        ip_configuration = {
            'name': self.create_resource_name(['ip-config']),
            'subnet_id': self.__get_azure_network_resource_uri(
                terraform_resource_type='azurerm_subnet',
                azure_resource_name=instance['azurerm_subnet'],
                azure_virtual_network_name=instance['azurerm_virtual_network']),
            'private_ip_address_allocation': 'Dynamic',
            'public_ip_address_id': self.__get_azure_network_resource_uri(
                terraform_resource_type='azurerm_public_ip',
                azure_resource_name=instance['azurerm_public_ip'])
        }

        new_nic = {
            'name': name,
            'location': instance['location'],
            'resource_group_name': self.resource_group,
            'ip_configuration': ip_configuration,
            'depends_on': [
                'azurerm_virtual_network.{}'.format(instance['azurerm_virtual_network']),
                'azurerm_subnet.{}'.format(instance['azurerm_subnet']),
                'azurerm_public_ip.{}'.format(instance['azurerm_public_ip']),
            ]
        }
        self.add_tags(self.config, new_nic)

        self.resources_tf['resource']['azurerm_network_interface'][name] = new_nic

    def __new_azure_vm(self, instance):
        if 'instance_type' not in instance or instance['instance_type'] == '':
            instance['instance_type'] = self.default_vm_size

        instance_hostname = instance['hostname']

        if 'username' in instance:
            instance_user = instance['username']
        else:
            instance_user = self.default_admin_username

        os_disk = {
            'caching': 'ReadWrite',
            'storage_account_type': 'Standard_LRS',
        }

        admin_ssh_key = {
            'username': instance_user,
            'public_key': f'${{file("{self.ssh_key_path}")}}'
        }

        new_instance = {
            'name': instance_hostname,
            'location': instance['location'],
            'admin_username': instance_user,
            'size': instance['instance_type'],
            'resource_group_name': self.resource_group,
            'network_interface_ids': [self.__get_azure_network_resource_uri(
                terraform_resource_type='azurerm_network_interface',
                azure_resource_name=instance['azurerm_network_interface'])],
            'os_disk': os_disk,
            'admin_ssh_key': admin_ssh_key,
            'depends_on': [
                'azurerm_virtual_network.{}'.format(instance['azurerm_virtual_network']),
                'azurerm_subnet.{}'.format(instance['azurerm_subnet']),
                'azurerm_network_interface.{}'.format(instance['azurerm_network_interface']),
            ]
        }
        self.add_tags(self.config, new_instance)

        if 'image_uri' in instance:
            new_instance['source_image_id'] = instance['image_uri']
        elif 'image_definition' in instance:
            new_instance['source_image_reference'] = instance['image_definition']
            if 'plan' in instance:
                new_instance['plan'] = instance['plan']
        elif 'vhd_uri' in instance:
            new_instance['depends_on'].append('azurerm_image.{}'.format(instance['image_from_vhd']))
            new_instance['source_image_id'] = self.__get_azure_image_uri(instance['image_from_vhd'])

        self.resources_tf['resource']['azurerm_linux_virtual_machine'][instance_hostname] = new_instance

    def __get_azure_image_uri(self, azure_image_name):
        """
        Returns a composed string URI that belongs to a specific Azure image, from its name
        :param azure_image_name: The name of the image as it was created in Azure
        :return: String
        """
        return '{}/Microsoft.Compute/images/{}'.format(self.azure_resource_id_base, azure_image_name)

    def __get_azure_network_resource_uri(self,
                                         terraform_resource_type,
                                         azure_resource_name,
                                         azure_virtual_network_name=None):
        """
        :param terraform_resource_type: The Terraform resource type
        :param azure_resource_name: The resource name as created in Azure
        :param azure_virtual_network_name: (Optional) The Virtual Network name as created in Azure.
                                                      Needed for 'azurerm_subnet' resource type.
        :return: (String) Azure resource URI
        """
        resource = 'Microsoft.Network'

        tf_azure_resource_types = {
            'azurerm_virtual_network': f'{self.azure_resource_id_base}/{resource}/virtualNetworks/{azure_resource_name}',
            'azurerm_subnet': f'{self.azure_resource_id_base}/{resource}/virtualNetworks/{azure_virtual_network_name}/subnets/{azure_resource_name}',
            'azurerm_public_ip': f'{self.azure_resource_id_base}/{resource}/publicIPAddresses/{azure_resource_name}',
            'azurerm_network_interface': f'{self.azure_resource_id_base}/{resource}/networkInterfaces/{azure_resource_name}',
        }

        if terraform_resource_type not in tf_azure_resource_types:
            raise f'Unexpected azure resource type. supported types are: {tf_azure_resource_types.keys()}'

        if terraform_resource_type == 'azurerm_subnet' and azure_virtual_network_name is None:
            raise 'Expected azurerm_virtual_network resource name to build azurerm_subnet resource id.'

        return tf_azure_resource_types[terraform_resource_type]
