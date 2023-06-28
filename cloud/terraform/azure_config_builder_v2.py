import re

from cloud.terraform.base_config_builder import BaseConfigBuilder


class AzureConfigBuilderV2(BaseConfigBuilder):
    cloud_name = 'azure'
    cloud_provider_definition = {'azurerm': {'source': 'hashicorp/azurerm', 'version': '~> 3.51.0'}}

    default_x86_vm_size = 'Standard_DS1_v2'
    default_arm64_vm_size = 'Standard_D2pls_v5'
    default_admin_username = 'azure'
    default_location = 'eastus'
    default_publisher = 'RedHat'

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
        self.resources_tf['resource']['azurerm_public_ip'] = {}
        self.resources_tf['resource']['azurerm_network_interface'] = {}
        self.resources_tf['resource']['azurerm_linux_virtual_machine'] = {}
        # Only applicable if vhd_uri is provided in resources.json
        self.resources_tf['resource']['azurerm_shared_image_gallery'] = {}
        self.resources_tf['resource']['azurerm_shared_image'] = {}
        self.resources_tf['resource']['azurerm_shared_image_version'] = {}

        for instance in self.resources_dict['instances']:
            instance['hostname'] = self.create_resource_name(['vm'])

            if 'location' in instance:
                instance['location'] = instance['location'].lower().replace(' ', '')
            else:
                instance['location'] = self.default_location

            self.__new_azure_virtual_network(instance)
            self.__new_azure_subnet(instance)

            if 'vhd_uri' in instance:
                self.__new_azure_shared_image_gallery(instance)
                self.__new_azure_shared_image(instance)
                self.__new_azure_shared_image_version(instance)

            self.__new_azure_public_ip(instance)
            self.__new_azure_nic(instance)
            self.__new_azure_vm(instance)

        if not self.resources_tf['resource']['azurerm_shared_image_gallery']:
            del self.resources_tf['resource']['azurerm_shared_image_gallery']

        if not self.resources_tf['resource']['azurerm_shared_image']:
            del self.resources_tf['resource']['azurerm_shared_image']

        if not self.resources_tf['resource']['azurerm_shared_image_version']:
            del self.resources_tf['resource']['azurerm_shared_image_version']

        return self.resources_tf

    def __parse_vhd_name(self, vhd_uri):
        """Parse a vhd name and return extracted image details

        Regex101: https://regex101.com/r/almD3W/2

        Args:
            vhd_uri: Image uri.
        Returns:
            Dictionary with additional information about the vhd.
        """
        #     product_name = one of the EXD-SP defined Azure product names e.g. rhel-sap-azure
        #     See https://docs.google.com/document/d/19EiQ-XyvsUo4r-u-SFetVJ_P8M96mwtEyuuDKpqMb0c/edit#
        #     for Stratosphere naming conventions.
        #     version = RHEL version in MAJOR.MINOR(.PATCH)
        #     date = date image was produced
        #     build_nr = integer of builditeration performed on the build date
        #     arch = architecture

        azure_vhd_regex = (
            r"https:\/\/(?P<storage_account>.*)\.blob.*\/(?P<product_name>\D*)\-(?P<version>[\d]+\.[\d]+(?:\.[\d]+)?)\-"
            r"(?P<date>\d{4}\d{2}\d{2})\.\b(?:sp\.)?(?P<build_nr>\d+)\.(?P<arch>\S*)\.\bvhd"
        )

        azure_vhd_regex_image_builder = (
            r"https:\/\/(?P<storage_account>.*)\.blob.*\/image-(?P<product_name>.*)-"
            r"(?P<version>\d+)-(?P<arch>x86_64|aarch64).*.vhd"
        )

        matches = re.match(azure_vhd_regex, vhd_uri, re.IGNORECASE)
        matches_image_builder = re.match(azure_vhd_regex_image_builder, vhd_uri, re.IGNORECASE)

        vhd_data = matches.groupdict() if matches else matches_image_builder.groupdict()

        return vhd_data

    def __new_azure_shared_image_gallery(self, instance):
        name = self.create_resource_name(['gallery'], separator='_')
        instance['azurerm_shared_image_gallery'] = name

        new_image_gallery = {
            'name': name,
            'resource_group_name': self.resource_group,
            'location': instance['location']
        }
        self.add_tags(self.config, new_image_gallery)

        self.resources_tf['resource']['azurerm_shared_image_gallery'][name] = new_image_gallery

    def __new_azure_shared_image(self, instance):
        vhd_properties = self.__parse_vhd_name(instance['vhd_uri'])
        instance['vhd_properties'] = vhd_properties

        product = vhd_properties['product_name']
        version = vhd_properties['version'].replace(".", "-")

        if vhd_properties['arch'] == 'aarch64':
            arch = 'Arm64'
        else:
            arch = 'x64'

        instance['arch'] = arch

        name = self.create_resource_name([product, version, arch])
        instance['azurerm_shared_image'] = name

        identifier = {
            'publisher': self.default_publisher,
            'offer': product.upper(),
            'sku': version
        }

        new_image_definition = {
            'name': name,
            'gallery_name': instance['azurerm_shared_image_gallery'],
            'resource_group_name': self.resource_group,
            'location': instance['location'],
            'os_type': 'Linux',
            'identifier': identifier,
            'hyper_v_generation': 'V2',
            'architecture': arch,
            'depends_on': [
                'azurerm_shared_image_gallery.{}'.format(instance['azurerm_shared_image_gallery']),
            ]
        }
        self.add_tags(self.config, new_image_definition)

        self.resources_tf['resource']['azurerm_shared_image'][name] = new_image_definition

    def __new_azure_shared_image_version(self, instance):
        name = self.create_resource_name([instance['azurerm_shared_image'], 'img-version'])
        instance['azurerm_shared_image_version'] = name

        target_region = {
            'name': instance['location'],
            'regional_replica_count': 1
        }

        new_image = {
            'name': '0.0.1',
            'blob_uri': instance['vhd_uri'],
            'storage_account_id': self.__get_azure_storage_account_uri(instance['vhd_properties']['storage_account']),
            'image_name': instance['azurerm_shared_image'],
            'location': instance['location'],
            'resource_group_name': self.resource_group,
            'gallery_name': instance['azurerm_shared_image_gallery'],
            'target_region': target_region,
            'depends_on': [
                'azurerm_shared_image_gallery.{}'.format(instance['azurerm_shared_image_gallery']),
                'azurerm_shared_image.{}'.format(instance['azurerm_shared_image']),
            ]
        }
        self.add_tags(self.config, new_image)

        self.resources_tf['resource']['azurerm_shared_image_version'][name] = new_image

    def __new_azure_virtual_network(self, instance):
        name = self.create_resource_name([instance['location'], 'network'])
        instance['azurerm_virtual_network'] = name

        new_virtual_network = {
            'name': name,
            'address_space': ['10.0.0.0/16'],
            'location': instance['location'],
            'resource_group_name': self.resource_group,
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
            'domain_name_label': instance['hostname'],
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
        # If no architecture is specified, and we are not deploying from vhd URI, we will assume it's x64 arch
        if 'arch' not in instance or instance['arch'] == '' or not instance['arch']:
            instance['arch'] = 'x86_64'

        if 'instance_type' not in instance or instance['instance_type'] == '' or not instance['instance_type']:
            if instance['arch'] == 'Arm64':
                instance['instance_type'] = self.default_arm64_vm_size
            else:
                instance['instance_type'] = self.default_x86_vm_size

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
            new_instance['depends_on'].append(
                'azurerm_shared_image_version.{}'.format(instance['azurerm_shared_image_version']))
            new_instance['source_image_id'] = self.__get_azure_image_uri(instance['azurerm_shared_image_gallery'],
                                                                         instance['azurerm_shared_image'])

        self.resources_tf['resource']['azurerm_linux_virtual_machine'][instance_hostname] = new_instance

    def __get_azure_storage_account_uri(self, storage_account_name):
        """
        Returns a composed string URI that belongs to a specific Storage Account, from its name
        :param storage_account_name: The name of the Storage Account in Azure
        :return: String
        """
        return '/subscriptions/{0}/resourceGroups/rh-resource/providers/Microsoft.Storage/storageAccounts/{1}'\
            .format(self.subscription_id, storage_account_name)

    def __get_azure_image_uri(self, azure_image_gallery_name, azure_image_name):
        """
        Returns a composed string URI that belongs to a specific Azure image, from its name
        :param azure_image_name: The name of the image as it was created in Azure
        :return: String
        """
        return '{}/Microsoft.Compute/galleries/{}/images/{}'.format(self.azure_resource_id_base,
                                                                    azure_image_gallery_name,
                                                                    azure_image_name)

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
