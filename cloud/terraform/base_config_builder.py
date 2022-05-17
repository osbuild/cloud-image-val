import random


class BaseConfigBuilder:
    cloud_name = None
    cloud_provider_definition = None

    cloud_providers = {
        'aws': 'aws',
        'azure': 'azurerm',
    }

    def __init__(self, resources_dict):
        self.resources_dict = resources_dict

        self.resources_tf = {'resource': {}}
        self.providers_tf = {'provider': {self.cloud_providers[self.cloud_name]: []}}

        self.random_str = f'-{random.randrange(1, 10**5):03}'

    def build_resources(self) -> dict:
        pass

    def build_providers(self) -> dict:
        pass
