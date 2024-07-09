import json
import time
import pytest
from lib import console_lib
from lib import test_lib


@pytest.fixture()
def check_instance_status(instance_data, host, timeout_seconds=300):
    instance_id = instance_data['instance_id']
    instance_region = instance_data['availability_zone'][:-1]
    command_to_run = [
        'aws', 'ec2', 'describe-instance-status',
        '--instance-ids', instance_id, '--region', instance_region
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


@pytest.fixture()
def modify_iam_role(instance_data, host):
    instance_id = instance_data['instance_id']
    region = instance_data['availability_zone'][:-1]
    iam_role_name = "CloudWatchAgentServerRole_2"

    command_to_run = [
        'aws', 'ec2', 'associate-iam-instance-profile',
        '--instance-id', instance_id,
        '--region', region,
        '--iam-instance-profile', 'Name="{}"'.format(iam_role_name)
    ]
    modify_iam_role_cmd = ' '.join(command_to_run)

    assert host.backend.run_local(modify_iam_role_cmd), 'faild to update iam role'


@pytest.fixture()
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


@pytest.fixture()
def install_packages(request, host):
    class_instance = request.node.cls
    install_cmd = (f'dnf copr enable frzifus/{class_instance.package_name} -y'
                   f' && dnf install -y opentelemetry-collector')

    with host.sudo():
        assert host.run(install_cmd).succeeded, f'Failed to install the package {class_instance.package_name}'
        test_lib.print_host_command_output(host, "rpm -qa | grep opentelemetry*")

    def finalizer():
        console_lib.print_divider(f'Removing the package {class_instance.package_name}')
        assert host.run(f'sudo yum remove -y {class_instance.package_name}')
        assert not host.check_output(f'rpm -q {class_instance.package_name}')
        assert host.run(f'ssh {class_instance.instance_dns}').failed
        console_lib.print_divider("Verify logs don't appear")
        # TODO: verify logs don't appear.
    request.addfinalizer(finalizer)


@pytest.fixture()
def start_service(request, host):
    class_instance = request.node.cls
    start_service = (f'systemctl start {class_instance.service_name}')
    enable_service = (f'systemctl enable {class_instance.service_name}')
    is_active = (f'systemctl is-active {class_instance.service_name}')

    with host.sudo():
        assert host.run(start_service).succeeded, (f'Failed to start the service {class_instance.service_name}')
        assert host.run(enable_service).succeeded, (f'Failed to enable the service {class_instance.service_name}')
        assert host.run(is_active).succeeded, (f'Service is not active {class_instance.service_name}')


@pytest.mark.package
@pytest.mark.run_on(['rhel9.4'])
class TestOtel():
    package_name = 'redhat-opentelemetry-collector-main'
    service_name = 'opentelemetry-collector.service'

    def check_aws_cli_logs(self, host, region):
        command_to_run = [
            'export', f'AWS_REGION={region}', "&&",
            'aws', 'logs', 'filter-log-events',
            '--log-stream-names', '"testing-integrations-stream-emf"',
            '--filter-pattern', '"Invalid"',
            '--log-group-name', '"testing-logs-emf"'
        ]
        run_aws_cli_cmd = ' '.join(command_to_run)

        command_output = host.backend.run_local(run_aws_cli_cmd)
        assert "Invalid user" in command_output

    @pytest.mark.usefixtures(
        check_instance_status.__name__,
        install_packages.__name__,
        setup_conf.__name__,
        modify_iam_role.__name__,
        start_service.__name__
    )
    def test_otel(self, host, instance_data):
        """
        Verify basic funstionality for OpenTelemetry (OTEL) package:
            - Install the package.
            - Start the service.
            - Modify IAM role.
            - Make a failure ssh connection to the instance.
            - Check for error messages in the ssh logs cotaining within the instance.
            - Check the error logs with AWS CLI and compare it to the logs in "/var/log/secure".
        Finalize:
            - Remove the package from the instance and verify it's not present anymore.
            - Try a failure ssh again and check that the logs don't appear.
        """
        instance_dns = instance_data['public_dns']
        instance_region = instance_data['availability_zone'][:-1]
        with host.sudo():
            console_lib.print_divider("Connect to the instance without a key in order to fail")
            result = host.backend.run_local(f'ssh -o BatchMode=yes {instance_dns}').stderr
            assert "Host key verification failed" in result or "Permission denied" in result

            console_lib.print_divider("Check for error logs in the instance logs")
            assert host.run('echo "" > /var/log/secure')

            for attempt in range(3):
                try:
                    host.backend.run_local(f'ssh -o BatchMode=yes {instance_dns}')
                    invalid = host.run('cat /var/log/secure | grep "invalid user"').stdout
                    assert "invalid" in invalid, ('no logs of ssh connection failure exist')
                except AssertionError as e:
                    print(f"AssertionError: {e}")
                time.sleep(15)

        console_lib.print_divider("Check for error logs in aws cli logs")
        self.check_aws_cli_logs(host, instance_region)
