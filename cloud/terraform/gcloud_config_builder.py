from cloud.terraform.base_config_builder import BaseConfigBuilder


class GCloudConfigBuilder(BaseConfigBuilder):
    cloud_name = 'gcloud'
    cloud_provider_definition = {'google': {'source': 'hashicorp/google', 'version': '~> 3.5.0'}}

    default_ssh_user = 'user'

    ssh_enabled_tag = 'ssh-enabled'

    def __init__(self, resources_dict, ssh_key_path):
        super().__init__(resources_dict)

        self.ssh_key_path = ssh_key_path
        self.project = resources_dict['project']

    def build_providers(self):
        all_regions = self.__get_all_regions_from_resources_file()
        for region in all_regions:
            self.providers_tf['provider'][self.cloud_providers[self.cloud_name]]\
                .append(self.__new_gcloud_provider(self.project, region))

        return self.providers_tf

    def __get_all_regions_from_resources_file(self):
        instances_regions = [i['region'] for i in self.resources_dict['instances']]

        return list(dict.fromkeys(instances_regions))

    def __new_gcloud_provider(self, project, region):
        zone = f'{region}-c'

        return {
            'project': project,
            'region': region,
            'zone': zone,
        }

    def build_resources(self):
        self.resources_tf['resource']['google_compute_network'] = {}
        self.resources_tf['resource']['google_compute_firewall'] = {}
        self.resources_tf['resource']['google_compute_instance'] = {}

        network_name = self.create_resource_name(['vpc'])

        self.__new_gcloud_network(network_name)
        self.__new_gcloud_firewall_rule(network_name)

        for instance in self.resources_dict['instances']:
            instance['google_compute_network'] = network_name
            self.__new_gcloud_instance(instance)

        return self.resources_tf

    def __new_gcloud_firewall_rule(self, network_name):
        name = self.create_resource_name(['firewall-rule'])

        allow_rule = {
            'protocol': 'tcp',
            'ports': ['22'],
        }

        new_rule = {
            'name': name,
            'network': network_name,
            'target_tags': [self.ssh_enabled_tag],
            'source_ranges': ['0.0.0.0/0'],
            'allow': allow_rule,
            'depends_on': [
                'google_compute_network.{}'.format(network_name)
            ],
        }

        self.resources_tf['resource']['google_compute_firewall'][name] = new_rule

    def __new_gcloud_network(self, network_name):
        new_vpc = {
            'name': network_name,
            'auto_create_subnetworks': True
        }

        self.resources_tf['resource']['google_compute_network'][network_name] = new_vpc

    def __new_gcloud_instance(self, instance):
        if not instance['instance_type']:
            instance['instance_type'] = 'e2-micro'

        # Google instance names must match the following regex: '(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)'
        formatted_name = instance['name'].replace('.', '-').replace('_', '-')
        name = self.create_resource_name([formatted_name])

        aliases = [provider['region'] for provider in self.providers_tf['provider'][self.cloud_providers[self.cloud_name]]]
        if instance['region'] not in aliases:
            raise Exception('Cannot add an instance if region provider is not set up')

        boot_disk = {
            'initialize_params': {
                'image': instance['image']
            }
        }

        network_interface = {
            'network': instance['google_compute_network'],
            'access_config': {}
        }

        if 'username' in instance:
            username = instance['username']
        else:
            username = self.default_ssh_user

        metadata = {
            'ssh-keys': f'{username}:${{file("{self.ssh_key_path}")}}',
            'image': instance['image'],
            'username': username,
        }

        new_instance = {
            'name': name,
            'machine_type': instance['instance_type'],
            'boot_disk': boot_disk,
            'zone': instance['zone'],
            'network_interface': network_interface,
            'metadata': metadata,
            'tags': [self.ssh_enabled_tag, self.ci_tag_key],
            'depends_on': [
                'google_compute_network.{}'.format(instance['google_compute_network'])
            ]
        }

        self.resources_tf['resource']['google_compute_instance'][name] = new_instance
