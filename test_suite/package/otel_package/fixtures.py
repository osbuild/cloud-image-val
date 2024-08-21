import json
import re
import time
import pytest
from lib import console_lib
from lib import test_lib
from test_suite.generic import helpers


@pytest.fixture(scope='class')
def initialize_variables(request, host):
    self = request.node.cls
    values_to_find = [host.backend.hostname] + host.addr(host.backend.hostname).ipv4_addresses
    instance_data = helpers.__get_instance_data_from_json(key_to_find='address', values_to_find=values_to_find)
    self.instance_id = instance_data['instance_id']
    self.instance_dns = instance_data['public_dns']
    self.instance_region = instance_data['availability_zone'][:-1]


@pytest.fixture(scope='function')
def check_instance_status(request, host, timeout_seconds=300):
    self = request.node.cls
    command_to_run = [
        'aws', 'ec2', 'describe-instance-status',
        '--instance-ids', self.instance_id, '--region', self.instance_region
    ]

    start_time = time.time()
    while True:
        if time.time() - start_time > timeout_seconds:
            raise TimeoutError("Timeout exceeded while waiting for instance status")

        command_output = host.backend.run_local(" ".join(command_to_run)).stdout
        cmd_output = json.loads(command_output)

        instance_status = cmd_output["InstanceStatuses"][0]["InstanceStatus"]["Status"]
        system_status = cmd_output["InstanceStatuses"][0]["SystemStatus"]["Status"]

        if instance_status == "ok" and system_status == "ok":
            break
        else:
            print("Instance status is not 'passed' yet. Waiting...")
            time.sleep(5)


@pytest.fixture(scope='function')
def modify_iam_role(request, host):
    self = request.node.cls
    iam_role_name = "CloudWatchAgentServerRole_2"

    command_to_run = [
        'aws', 'ec2', 'associate-iam-instance-profile',
        '--instance-id', self.instance_id,
        '--region', self.instance_region,
        '--iam-instance-profile', 'Name="{}"'.format(iam_role_name)
    ]
    modify_iam_role_cmd = ' '.join(command_to_run)
    assert host.backend.run_local(modify_iam_role_cmd), 'faild to update iam role'


@pytest.fixture(scope='function')
def setup_conf(host):
    file_path = '/etc/opentelemetry-collector/configs/10-cloudwatch-export.yaml'
    file_content = """
---
exporters:
  awscloudwatchlogs:
    log_group_name: "testing-logs-emf"
    log_stream_name: "testing-integrations-stream-emf"

service:
  pipelines:
    logs:
      receivers: [journald]
      exporters: [awscloudwatchlogs]

    """
    with host.sudo():
        host.run(f"echo '{file_content}' > {file_path}")


@pytest.fixture(scope='function')
def install_packages(request, host):
    self = request.node.cls
    with host.sudo():
        test_lib.print_host_command_output(host, "rpm -qa | grep opentelemetry*")

    def finalizer():
        console_lib.print_divider(f'Removing the package {self.package_name}')
        assert host.run(f'sudo yum remove -y {self.package_name}')
        cmd_output = host.run(f'rpm -q {self.package_name}').stdout
        assert "package redhat-opentelemetry-collector-main is not installed" in cmd_output
        assert host.run(f'ssh {self.instance_dns}').failed
        console_lib.print_divider("Verify logs don't appear")
        log_output = self.check_aws_cli_logs(self, host, self.instance_region).stdout
        assert re.search(r"invalid\s+user", log_output), "Expected 'invalid user' not found in logs"
    request.addfinalizer(finalizer)


@pytest.fixture(scope='function')
def start_service(request, host):
    self = request.node.cls
    start_service = (f'systemctl start {self.service_name}')
    enable_service = (f'systemctl enable {self.service_name}')
    is_active = (f'systemctl is-active {self.service_name}')

    with host.sudo():
        assert host.run(start_service).succeeded, (f'Failed to start the service {self.service_name}')
        assert host.run(enable_service).succeeded, (f'Failed to enable the service {self.service_name}')
        assert host.run(is_active).succeeded, (f'Service is not active {self.service_name}')
