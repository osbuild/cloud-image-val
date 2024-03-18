import random


class BaseConfigBuilder:
    cloud_name = None
    cloud_provider_definition = None

    cloud_providers = {
        'aws': 'aws',
        'azure': 'azurerm',
        'gcloud': 'google',
    }

    resource_name_prefix = 'civ'
    resource_tags_key = 'tags'

    def __init__(self, resources_dict, ssh_key_path, config):
        self.resources_dict = resources_dict
        self.ssh_key_path = ssh_key_path
        self.config = config

        self.resources_tf = {'resource': {}}
        self.providers_tf = {'provider': {self.cloud_providers[self.cloud_name]: []}}

    def build_resources(self) -> dict:
        pass

    def build_providers(self) -> dict:
        pass

    def create_resource_name(self, resource_names_combination, separator='-') -> str:
        """
        Returns a resource name with the items provided in the parameters, plus civ identifier and random number
        Example: Given ['vm', 'eastus'] as resource_names_combination param, you will get 'civ-vm-eastus-XXXXX'
                 (where XXXXX are a random series of digits)
        :param resource_names_combination: List of keywords, names or IDs that you want to include in the resource name.
                                           Example: ['westeurope', 'vm']
        :param separator: String to be used as a separator of the items passed in resource_names_combination
        :return: String composed of a prefix, resource names combination and a suffix with random numbers.
        """
        tf_resource_name_max_chars = 63
        random_num = self.get_random_numbers()

        # If any of the names already have prefixes, those will be removed to avoid redundancy.
        # Example: We received ['civ-network', 'vnc'] as resource_names_combination argument.
        # Considering self.resource_name_prefix is "civ" and separator "-", combined_name will contain: "network-vnc"
        combined_name = separator.join(resource_names_combination).replace(
            f'{self.resource_name_prefix}{separator}', '')

        # We calculate the full length after concatenation with prefix, two separators and random numbers
        end_index = tf_resource_name_max_chars - len(self.resource_name_prefix) - len(random_num) - (len(separator) * 2)

        combinations = [
            self.resource_name_prefix,
            combined_name[0:end_index],
            random_num
        ]

        return separator.join(combinations)

    def get_random_numbers(self):
        return f'{random.randrange(1, 10 ** 5):03}'

    def add_tags(self, config_dict, resource):
        tags_key = self.resource_tags_key

        if config_dict['tags']:
            if tags_key in resource:
                resource[tags_key] = {**resource[tags_key], **config_dict['tags']}
            else:
                resource[tags_key] = config_dict['tags']
