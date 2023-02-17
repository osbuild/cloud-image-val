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
    ci_tag_key = 'civ-ci'
    ci_test_value = 'true'

    def __init__(self, resources_dict):
        self.resources_dict = resources_dict

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
        combinations = [self.resource_name_prefix]
        combinations.extend(resource_names_combination)
        combinations.append(self.get_random_numbers())

        return separator.join(combinations)

    def get_random_numbers(self):
        return f'{random.randrange(1, 10 ** 5):03}'
