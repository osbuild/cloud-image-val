import os
import json
import re

from threading import Thread
from lib import ssh_lib


class OpenTofuController:
    def __init__(self, tf_configurator, debug=False):
        self.cloud_name = tf_configurator.cloud_name
        self.tf_configurator = tf_configurator
        self.debug = debug

        self.debug_sufix = ''
        if not debug:
            self.debug_sufix = '1> /dev/null'

    def create_infra(self):
        self.failed_deployments = []

        cmd_output = os.system(f'tofu init {self.debug_sufix}')
        if cmd_output:
            raise Exception('tofu init command failed, check configuration')

        cmd_output = os.system(f'tofu apply -auto-approve {self.debug_sufix}')
        if cmd_output:
            created = self._count_created_instances()
            total = len(self.tf_configurator.resources_dict['instances'])
            if created == 0:
                raise Exception('tofu apply command failed and no instances were created, check configuration')
            failed = total - created
            self.failed_deployments = self._identify_failed_deployments()
            print(f'WARNING: tofu apply partially failed. '
                  f'{created} of {total} instances were created successfully, '
                  f'{failed} failed to deploy.', flush=True)
            for dep in self.failed_deployments:
                print(f'  - {dep["name"]} ({dep["region"]}): {dep["error"]}', flush=True)

        print('Waiting for the ssh server in the instance(s) to be ready...')
        self.wait_for_all_instances_ssh_up()

    def _count_created_instances(self):
        try:
            resources = self.get_opentofu_resources()
            instance_types = {
                'aws': 'aws_instance',
                'azure': 'azurerm_linux_virtual_machine',
                'gcloud': 'google_compute_instance',
                'oci': 'oci_core_instance',
            }
            instance_type = instance_types.get(self.cloud_name)
            return len([r for r in resources if r['type'] == instance_type])
        except Exception:
            return 0

    def _identify_failed_deployments(self):
        try:
            resources = self.get_opentofu_resources()
            instance_types = {
                'aws': 'aws_instance',
                'azure': 'azurerm_linux_virtual_machine',
                'gcloud': 'google_compute_instance',
                'oci': 'oci_core_instance',
            }
            instance_type = instance_types.get(self.cloud_name)
            created_names = {r['name'] for r in resources if r['type'] == instance_type}

            planned_instances = self.tf_configurator.resources_tf.get('resource', {}).get(instance_type, {})

            failed = []
            for tf_name, tf_config in planned_instances.items():
                if tf_name not in created_names:
                    region = tf_config.get('provider', '').replace(f'{self.cloud_name}.', '')
                    name_tag = tf_config.get('tags', {}).get('name', tf_name)
                    failed.append({
                        'name': name_tag,
                        'region': region or 'unknown',
                        'error': 'Instance failed to deploy (check tofu apply output for details)',
                    })
            return failed
        except Exception:
            return []

    def wait_for_all_instances_ssh_up(self):
        seconds_to_wait = 300
        instances = self.get_instances()

        threads = []
        for inst in instances.values():
            t = Thread(target=ssh_lib.wait_for_host_ssh_up,
                       args=[inst['address'], seconds_to_wait])
            t.start()
            threads.append(t)

        [t.join() for t in threads]

    def get_instances(self):
        resources = self.get_opentofu_resources()

        if self.cloud_name == 'aws':
            instances_info = self.get_instances_aws(resources)
        elif self.cloud_name == 'azure':
            instances_info = self.get_instances_azure(resources)
        elif self.cloud_name == 'gcloud':
            instances_info = self.get_instances_gcloud(resources)
        elif self.cloud_name == 'oci':
            instances_info = self.get_instances_oci(resources)
        else:
            raise Exception(f'Unsupported cloud provider: {self.cloud_name}')

        return instances_info

    def get_opentofu_resources(self):
        output = os.popen('tofu show --json')
        output = output.read()

        json_output = json.loads(output)

        return json_output['values']['root_module']['resources']

    def get_instances_aws(self, resources):
        regional_efs_file_systems = {}
        for resource in resources:
            if resource['type'] == 'aws_efs_file_system':
                efs_dns_name = resource['values']['dns_name']
                result = re.match(r'fs-.*\.efs\.(.*).amazon', efs_dns_name)

                if not result:
                    raise Exception(f'Could not get EFS file system region in DNS name: {efs_dns_name}')

                efs_region = result.group(1)

                regional_efs_file_systems[efs_region] = efs_dns_name

        instances_info = {}
        # 'address' key corresponds to the tf resource id
        for resource in resources:
            if resource['type'] != 'aws_instance':
                continue

            ami_name = resource['values']['ami']
            username = self.tf_configurator.get_aws_username_by_ami_name(ami_name)

            instance_data = {
                'cloud': 'aws',
                'name': resource['name'],
                'instance_id': resource['values']['id'],
                'public_ip': resource['values']['public_ip'],
                'public_dns': resource['values']['public_dns'],
                'private_ip': resource['values']['private_ip'],
                'availability_zone': resource['values']['availability_zone'],
                'ami': ami_name,
                'image': ami_name,
                'username': username,
                'image_type': self.tf_configurator.get_image_type(),
            }

            self._set_instance_default_address(instance_data)

            instance_region = instance_data['availability_zone'][:-1]
            if instance_region in regional_efs_file_systems.keys():
                instance_data['efs_file_system_dns_name'] = regional_efs_file_systems[instance_region]

            instances_info[resource['address']] = instance_data

        return instances_info

    def get_instances_azure(self, resources):
        instances_info = {}

        for res in resources:
            if res['type'] != 'azurerm_linux_virtual_machine':
                continue

            public_dns = self._get_azure_vm_fqdn_from_resources_json(res['name'], resources)

            image = self._get_azure_image_data_from_resource(res, resources)

            instance_data = {
                'cloud': 'azure',
                'name': res['name'],
                'instance_id': res['values']['id'],
                'public_ip': res['values']['public_ip_address'],
                'private_ip': res['values']['private_ip_address'],
                'public_dns': public_dns,
                'location': res['values']['location'],
                'image': image,
                'username': res['values']['admin_username'],
                'image_type': self.tf_configurator.get_image_type(),
            }

            self._set_instance_default_address(instance_data)

            instances_info[res['address']] = instance_data

        return instances_info

    def get_instances_gcloud(self, resources):
        instances_info = {}

        # 'address' key corresponds to the tf resource id
        for resource in resources:
            if resource['type'] != 'google_compute_instance':
                continue

            public_ip = resource['values']['network_interface'][0]['access_config'][0]['nat_ip']

            instances_info[resource['address']] = {
                'cloud': 'gcloud',
                'name': resource['name'],
                'instance_id': resource['values']['id'],
                'public_ip': public_ip,
                'public_dns': public_ip,  # TODO: Support also public dns as we do for the other Clouds
                'address': public_ip,  # TODO: Support also private IP addresses as we do for AWS
                'zone': resource['values']['zone'],
                'image': resource['values']['metadata']['image'],
                'username': resource['values']['metadata']['username'],
                'image_type': self.tf_configurator.get_image_type(),
            }

        return instances_info

    def get_instances_oci(self, resources):
        instances_info = {}

        for resource in resources:
            if resource['type'] != 'oci_core_instance':
                continue

            values = resource['values']

            public_ip = values.get('public_ip')

            instance_data = {
                'cloud': 'oci',
                'name': resource['name'],
                'instance_id': values['id'],
                'public_ip': public_ip,
                'public_dns': public_ip,  # OCI has no public DNS, use IP
                'private_ip': values.get('private_ip', ''),
                'availability_domain': values['availability_domain'],
                'shape': values['shape'],
                'image': values['source_details'][0]['source_id'],
                'username': self.tf_configurator.get_oci_username_by_instance_name(resource['name']),
                'image_type': self.tf_configurator.get_image_type(),
            }

            self._set_instance_default_address(instance_data)

            instances_info[resource['address']] = instance_data

        return instances_info

    def _set_instance_default_address(self, instance_data):
        if instance_data['public_dns']:
            inst_address = instance_data['public_dns']
        elif instance_data['public_ip']:
            inst_address = instance_data['public_ip']
        elif instance_data['private_ip']:
            inst_address = instance_data['private_ip']
        else:
            raise Exception('Could not find any valid instance address.')

        instance_data['address'] = inst_address

    def _get_azure_vm_fqdn_from_resources_json(self, vm_name, resources_json):
        for r in resources_json:
            if r['type'] == 'azurerm_public_ip' and \
                    r['values']['domain_name_label'] == vm_name:
                return r['values']['fqdn']

    def _get_azure_image_data_from_resource(self, vm_resource, all_resources):
        if 'source_image_reference' in vm_resource['values'] and \
                len(vm_resource['values']['source_image_reference']) > 0:
            return vm_resource['values']['source_image_reference']
        elif 'source_image_id' in vm_resource['values'] and \
                len(vm_resource['values']['source_image_id']) > 0:
            for r in all_resources:
                if r['type'] == 'azurerm_shared_image_version' and \
                        vm_resource['values']['source_image_id'] in r['values']['id']:
                    return r['values']['blob_uri']

            return vm_resource['values']['source_image_id']

    def destroy_resource(self, resource_id):
        cmd_output = os.system(f'tofu destroy -target={resource_id}')
        if cmd_output:
            raise Exception('tofu destroy specific resource command failed')

    def destroy_infra(self):
        cmd_output = os.system(f'tofu destroy -auto-approve {self.debug_sufix}')
        if cmd_output:
            raise Exception('tofu destroy command failed')
