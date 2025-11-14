import random

from cloud.opentofu.base_config_builder import BaseConfigBuilder


class AzureConfigBuilderV2(BaseConfigBuilder):
    cloud_name = 'azure'

    # Latest v4.x release.
    # https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/4.0-upgrade-guide
    provider_version = '4.52.0'
    cloud_provider_definition = {
        "azurerm": {"source": "hashicorp/azurerm", "version": f"~> {provider_version}"}
    }

    default_x86_vm_size = 'Standard_DS1_v2'
    default_arm64_vm_size = 'Standard_D2pls_v5'
    default_hyper_v_generation = 'V2'
    default_admin_username = 'azure'
    default_location = 'eastus'
    default_publisher = 'CIV'
    default_offer = 'civ'

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

        # NSG and Rule resources
        self.resources_tf['resource']['azurerm_network_security_group'] = {}
        self.resources_tf['resource']['azurerm_network_security_rule'] = {}

        self.resources_tf['resource']['azurerm_network_interface_security_group_association'] = {}
        # Only applicable if vhd_uri is provided in resources.json
        self.resources_tf['resource']['azurerm_shared_image_gallery'] = {}
        self.resources_tf['resource']['azurerm_shared_image'] = {}
        self.resources_tf['resource']['azurerm_shared_image_version'] = {}

        for instance in self.resources_dict['instances']:
            if 'name' in instance:
                formatted_instance_name = instance['name'].lower() \
                    .replace(' ', '-') \
                    .replace('.', '-') \
                    .replace('_', '-')

                instance['hostname'] = self.create_resource_name(['vm', formatted_instance_name])

            else:
                instance['hostname'] = self.create_resource_name(['vm'])

            if 'location' in instance:
                instance['location'] = instance['location'].lower().replace(' ', '')
            else:
                instance['location'] = self.default_location

            self.__new_azure_virtual_network(instance)
            self.__new_azure_subnet(instance)

            self.__new_azure_nsg(instance)
            self.__new_azure_nsg_rule(instance)

            if 'vhd_uri' in instance:
                required_data = ['arch', 'storage_account']
                for key in required_data:
                    if key not in instance:
                        raise Exception(f'"{key}" is mandatory for Azure instance definitions that use vhd blob URI.')

                self.__new_azure_shared_image_gallery(instance)
                self.__new_azure_shared_image(instance)
                self.__new_azure_shared_image_version(instance)

            self.__new_azure_public_ip(instance)
            self.__new_azure_nic(instance)
            self.__new_azure_nic_nsg_association(instance)
            self.__new_azure_vm(instance)

        if not self.resources_tf['resource']['azurerm_shared_image_gallery']:
            del self.resources_tf['resource']['azurerm_shared_image_gallery']

        if not self.resources_tf['resource']['azurerm_shared_image']:
            del self.resources_tf['resource']['azurerm_shared_image']

        if not self.resources_tf['resource']['azurerm_shared_image_version']:
            del self.resources_tf['resource']['azurerm_shared_image_version']

        return self.resources_tf

    def __new_azure_shared_image_gallery(self, instance):
        name = self.create_resource_name(['gallery'], separator='_')
        instance['azurerm_shared_image_gallery'] = name

        new_image_gallery = {
            'name': name,
            'resource_group_name': self.resource_group,
            'location': instance['location'],
            'tags': {
                'vhd_uri': instance['vhd_uri']
            }
        }
        self.add_tags(self.config, new_image_gallery)

        self.resources_tf['resource']['azurerm_shared_image_gallery'][name] = new_image_gallery

    def __new_azure_shared_image(self, instance):
        if instance['arch'] == 'aarch64':
            arch = 'Arm64'
        else:
            arch = 'x64'

        name = self.create_resource_name(['shared', 'image', arch])
        instance['azurerm_shared_image'] = name

        identifier = {
            'publisher': self.default_publisher,
            'offer': self.default_offer,
            'sku': f"{random.randint(1000, 9999)}.{random.randint(10, 99)}.{random.randint(10, 99)}"
        }

        if 'hyper_v_generation' in instance and instance['hyper_v_generation']:
            hyper_v_gen = instance['hyper_v_generation']
        else:
            hyper_v_gen = self.default_hyper_v_generation

        new_image_definition = {
            'name': name,
            'gallery_name': instance['azurerm_shared_image_gallery'],
            'resource_group_name': self.resource_group,
            'location': instance['location'],
            'os_type': 'Linux',
            'identifier': identifier,
            'hyper_v_generation': hyper_v_gen,
            'architecture': arch,
            'tags': {
                'vhd_uri': instance['vhd_uri']
            },
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
            'location': instance['location'],
            'resource_group_name': self.resource_group,
            'gallery_name': instance['azurerm_shared_image_gallery'],
            'image_name': instance['azurerm_shared_image'],
            'target_region': target_region,
            'blob_uri': instance['vhd_uri'],
            'storage_account_id': self.__get_azure_storage_account_uri(instance['storage_account']),
            'tags': {
                'vhd_uri': instance['vhd_uri']
            },
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

    def __new_azure_nsg(self, instance):
        name = self.create_resource_name([instance['hostname'], 'nsg'])
        instance['azurerm_network_security_group'] = name

        new_nsg = {
            'name': name,
            'location': instance['location'],
            'resource_group_name': self.resource_group,
        }
        self.add_tags(self.config, new_nsg)
        self.resources_tf['resource']['azurerm_network_security_group'][name] = new_nsg

    def __new_azure_nsg_rule(self, instance):
        name = self.create_resource_name([instance['hostname'], 'ssh-rule'])
        # The NSG rule resource name needs the name of the NSG resource it belongs to
        nsg_resource_name = instance['azurerm_network_security_group']

        new_rule = {
            'name': 'AllowSSH',
            'priority': 100,  # A low number ensures high priority
            'direction': 'Inbound',
            'access': 'Allow',
            'protocol': 'Tcp',
            'source_port_range': '*',
            'destination_port_range': '22',
            'source_address_prefix': '*',
            'destination_address_prefix': '*',
            'resource_group_name': self.resource_group,
            'network_security_group_name': nsg_resource_name,
            'depends_on': [
                f'azurerm_network_security_group.{nsg_resource_name}',
            ]
        }
        self.resources_tf['resource']['azurerm_network_security_rule'][name] = new_rule

    def __new_azure_nic_nsg_association(self, instance):
        # Name the association resource
        name = self.create_resource_name([instance['hostname'], 'nic-nsg-assoc'])

        new_association = {
            'network_interface_id': self.__get_azure_network_resource_uri(
                tf_resource_type='azurerm_network_interface',
                azure_resource_name=instance['azurerm_network_interface']),

            'network_security_group_id': self.__get_azure_network_resource_uri(
                tf_resource_type='azurerm_network_security_group',
                azure_resource_name=instance['azurerm_network_security_group']),

            'depends_on': [
                'azurerm_network_interface.{}'.format(instance['azurerm_network_interface']),
                'azurerm_network_security_group.{}'.format(instance['azurerm_network_security_group']),
            ]
        }

        self.resources_tf['resource']['azurerm_network_interface_security_group_association'][name] = new_association

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
                tf_resource_type='azurerm_subnet',
                azure_resource_name=instance['azurerm_subnet'],
                azure_virtual_network_name=instance['azurerm_virtual_network']),
            'private_ip_address_allocation': 'Dynamic',
            'public_ip_address_id': self.__get_azure_network_resource_uri(
                tf_resource_type='azurerm_public_ip',
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
                # Add NSG dependency
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

        boot_diagnostics = {
            'storage_account_uri': None
        }

        new_instance = {
            'name': instance_hostname,
            'location': instance['location'],
            'admin_username': instance_user,
            'size': instance['instance_type'],
            'resource_group_name': self.resource_group,
            'network_interface_ids': [self.__get_azure_network_resource_uri(
                tf_resource_type='azurerm_network_interface',
                azure_resource_name=instance['azurerm_network_interface'])],
            'os_disk': os_disk,
            'admin_ssh_key': admin_ssh_key,
            'boot_diagnostics': boot_diagnostics,
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
            new_instance['source_image_id'] = self.__get_azure_image_version_uri(
                instance['azurerm_shared_image_gallery'],
                instance['azurerm_shared_image'],
                '0.0.1'
            )

        self.resources_tf['resource']['azurerm_linux_virtual_machine'][instance_hostname] = new_instance

    def __get_azure_storage_account_uri(self, storage_account_name):
        """
        Returns a composed string URI that belongs to a specific Storage Account, from its name
        :param storage_account_name: The name of the Storage Account in Azure
        :return: String
        """
        return '/subscriptions/{0}/resourceGroups/rh-resource/providers/Microsoft.Storage/storageAccounts/{1}' \
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

    def __get_azure_image_version_uri(self, azure_image_gallery_name, azure_image_name, version_number):
        """
        Returns a composed string URI that belongs to a specific Azure shared image version.
        :param azure_image_gallery_name: The name of the Shared Image Gallery in Azure
        :param azure_image_name: The name of the Shared Image Definition in Azure
        :param version_number: The version number of the image (e.g. '0.0.1')
        :return: String
        """
        return '{}/Microsoft.Compute/galleries/{}/images/{}/versions/{}'.format(self.azure_resource_id_base,
                                                                                azure_image_gallery_name,
                                                                                azure_image_name,
                                                                                version_number)

    def __get_azure_network_resource_uri(self,
                                         tf_resource_type,
                                         azure_resource_name,
                                         azure_virtual_network_name=None):
        """
        :param tf_resource_type: The OpenTofu resource type
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
            # Add Network Security Group
            'azurerm_network_security_group': f'{self.azure_resource_id_base}/{resource}/networkSecurityGroups/{azure_resource_name}',
        }

        if tf_resource_type not in tf_azure_resource_types:
            raise f'Unexpected azure resource type. supported types are: {tf_azure_resource_types.keys()}'

        if tf_resource_type == 'azurerm_subnet' and azure_virtual_network_name is None:
            raise 'Expected azurerm_virtual_network resource name to build azurerm_subnet resource id.'

        return tf_azure_resource_types[tf_resource_type]
