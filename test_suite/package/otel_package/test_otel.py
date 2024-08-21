import time
import pytest
from lib import console_lib
from test_suite.generic import helpers
from test_suite.package.otel_package.fixtures import (
    initialize_variables, check_instance_status,
    install_packages, setup_conf, modify_iam_role, start_service, run_subscription_manager_auto
)


@pytest.mark.package
@pytest.mark.run_on(['>=rhel9.5'])
@pytest.mark.usefixtures(
    initialize_variables.__name__
)
class TestOtel:
    package_name = 'redhat-opentelemetry-collector-main'
    service_name = 'opentelemetry-collector.service'

    def check_aws_cli_logs(self, host, region):
        command_to_run = [
            'export', f'AWS_REGION={self.instance_region}', "&&",
            'aws', 'logs', 'filter-log-events',
            '--log-stream-names', '"testing-integrations-stream-emf"',
            '--filter-pattern', '"Invalid"',
            '--log-group-name', '"testing-logs-emf"'
        ]
        run_aws_cli_cmd = ' '.join(command_to_run)
        return host.backend.run_local(run_aws_cli_cmd)

    @pytest.mark.usefixtures(
        run_subscription_manager_auto.__name__,
        check_instance_status.__name__,
        install_packages.__name__,
        setup_conf.__name__,
        modify_iam_role.__name__,
        start_service.__name__
    )
    def test_otel(self, host):
        """
        Verify basic funstionality for OpenTelemetry (OTEL) package:
            - Install the package.
            - Start the service.
            - Modify IAM role.
            - Make a failure ssh connection to the instance.
            - Check for error messages in the ssh logs cotaining within the instance.
            - Check the error logs with AWS CLI and compare it to the logs in "/var/log/secure".
            - Check there are no AVC denials.
        Finalize:
            - Remove the package from the instance and verify it's not present anymore.
            - Try a failure ssh again and check that the logs don't appear.
        """
        with host.sudo():
            console_lib.print_divider("Connect to the instance without a key in order to fail")
            result = host.backend.run_local(f'ssh -o BatchMode=yes {self.instance_dns}').stderr
            assert "Host key verification failed" in result or "Permission denied" in result

            console_lib.print_divider("Check for error logs in the instance logs")
            assert host.run('echo "" > /var/log/secure')

            for attempt in range(3):
                try:
                    host.backend.run_local(f'ssh -o BatchMode=yes {self.instance_dns}')
                    invalid = host.run('cat /var/log/secure | grep "invalid user"').stdout
                    assert "invalid" in invalid, ('no logs of ssh connection failure exist')
                except AssertionError as e:
                    print(f"AssertionError: {e}")
                time.sleep(15)

        console_lib.print_divider("Check for error logs in aws cli logs")
        assert "Invalid user" in self.check_aws_cli_logs(host, self.instance_region)

        helpers.check_avc_denials(host)
