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
        cmd_output = os.system(f'tofu init {self.debug_sufix}')
        if cmd_output:
            raise Exception('tofu init command failed, check configuration')

        cmd_output = os.system(f'tofu apply -auto-approve {self.debug_sufix}')
        if cmd_output:
            raise Exception('tofu apply command failed, check configuration')

        print('Waiting for the ssh server in the instance(s) to be ready...')
        self.wait_for_all_instances_ssh_up()

    def wait_for_all_instances_ssh_up(self):
        seconds_to_wait = 180
        instances = self.get_instances()

        threads = []
        for inst in instances.values():
            t = Thread(target=ssh_lib.wait_for_host_ssh_up,
                       args=[inst['public_dns'], seconds_to_wait])
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
                'availability_zone': resource['values']['availability_zone'],
                'ami': ami_name,
                'username': username,
            }

            instance_region = instance_data['availability_zone'][:-1]
            if instance_region in regional_efs_file_systems.keys():
                instance_data['efs_file_system_dns_name'] = regional_efs_file_systems[instance_region]

            instances_info[resource['address']] = instance_data

        return instances_info

    def get_instances_azure(self, resources):
        instances_info = {}

        for resource in resources:
            if resource['type'] != 'azurerm_linux_virtual_machine':
                continue

            public_dns = self._get_azure_vm_fqdn_from_resources_json(resource['name'],
                                                                     resources)

            image = self._get_azure_image_data_from_resource(resource)

            instances_info[resource['address']] = {
                'cloud': 'azure',
                'name': resource['name'],
                'instance_id': resource['values']['id'],
                'public_ip': resource['values']['public_ip_address'],
                'public_dns': public_dns,
                'location': resource['values']['location'],
                'image': image,
                'username': resource['values']['admin_username'],
            }

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
                'public_dns': public_ip,
                'zone': resource['values']['zone'],
                'image': resource['values']['metadata']['image'],
                'username': resource['values']['metadata']['username'],
            }

        return instances_info

    def _get_azure_vm_fqdn_from_resources_json(self, vm_name, resources_json):
        for r in resources_json:
            if r['type'] == 'azurerm_public_ip' and \
                    r['values']['domain_name_label'] == vm_name:
                return r['values']['fqdn']

    def _get_azure_image_data_from_resource(self, resource):
        if 'source_image_reference' in resource['values']:
            return resource['values']['source_image_reference']
        elif 'source_image_id' in resource['values']:
            return resource['values']['source_image_id']

    def destroy_resource(self, resource_id):
        cmd_output = os.system(f'tofu destroy -target={resource_id}')
        if cmd_output:
            raise Exception('tofu destroy specific resource command failed')

    def destroy_infra(self):
        cmd_output = os.system(f'tofu destroy -auto-approve {self.debug_sufix}')
        if cmd_output:
            raise Exception('tofu destroy command failed')
