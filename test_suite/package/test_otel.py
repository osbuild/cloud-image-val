import json
import time

import pytest

from lib import console_lib
from lib import test_lib
from test_suite.generic.test_generic import TestsSubscriptionManager


@pytest.fixture()
def check_instance_status(request, instance_data, host, timeout_seconds=300):
    instance_id = instance_data['instance_id']
    command_to_run = [
        'aws', 'ec2', 'describe-instance-status',
        '--instance-ids', instance_id
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
def install_packages(request, host):
    class_instance = request.node.cls
    install_cmd = f'yum install -y {class_instance.package_name} --nogpgcheck --skip-broken'
    repo_path = ('https://copr.fedorainfracloud.org/coprs/miyunari/redhat-opentelemetry-collector'
                 '/repo/rhel-9/miyunari-redhat-opentelemetry-collector-rhel-9.repo')
    with host.sudo():
        assert host.run(f'yum-config-manager --add-repo {repo_path}').succeeded
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
    start_enable_service = (
        f'systemctl start {class_instance.package_name} && '
        f'systemctl enable {class_instance.package_name}'
    )

    with host.sudo():
        assert host.run(start_enable_service).succeeded, (f'Failed to start the service {class_instance.package_name}')
        assert host.service(class_instance.package_name).is_enabled, (
            f'Failed to enable the service {class_instance.package_name}'
        )
        assert host.service(class_instance.package_name).is_running, (
            f'Failed to run the service {class_instance.package_name}'
        )


@pytest.fixture(autouse=True)
def run_subscription_manager_auto(request, host, instance_data):
    class_instance = request.node.cls
    console_lib.print_divider("Run the subscription manager auto test before any tests in this file")
    TestsSubscriptionManager.test_subscription_manager_auto(class_instance, host, instance_data)


@pytest.mark.package
@pytest.mark.run_on(['rhel9.4'])
class TestOtel:
    package_name = 'opentelemetry-collector-cloudwatch-config'

    def check_aws_cli_logs(self, host):
        command_to_run = [
            'aws', 'logs', 'filter-log-events',
            '--log-stream-names', 'testing-integrations-stream-emf',
            '--filter-pattern', 'Invalid',
            '--log-group-name', 'testing-logs-emf'
        ]
        run_aws_cli_cmd = ' '.join(command_to_run)

        command_output = host.backend.run_local(run_aws_cli_cmd).stdout
        assert "Invalid" in command_output

    @pytest.mark.usefixtures(
        check_instance_status.__name__,
        install_packages.__name__,
        modify_iam_role.__name__,
        start_service.__name__,
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
        console_lib.print_divider("Connect to the instance without a key in order to fail")
        instance_dns = instance_data['public_dns']
        result = host.backend.run_local(f'ssh -o BatchMode=yes {instance_dns}')
        assert "Host key verification failed" in result.stderr
        console_lib.print_divider("Check for error logs in the instance logs")
        with host.sudo():
            assert "Invalid" in host.file("/var/log/secure").content_string, \
                ('no logs regarding ssh connection failure exist')

        console_lib.print_divider("Check for error logs in aws cli logs")
        self.check_aws_cli_logs(host)
