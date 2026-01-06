import json
import pytest

from lib import test_lib
from packaging import version


@pytest.mark.package
@pytest.mark.run_on(['>=rhel9.5'])
@pytest.mark.usefixtures("fips_setup",
                         "log_fips_status")
class TestsAwsCli2:
    @pytest.fixture(scope='module', autouse=True)
    def import_aws_credentials(self, host, fips_setup):
        token_duration = 900  # This is the minimum accepted value in seconds
        # Generate temporary credentials for this test.

        fips_env = "AWS_USE_FIPS_ENDPOINT=true " if fips_setup else ""

        civ_local_command_to_run = (f'{fips_env}aws sts get-session-token '
                                    f'--duration-seconds {token_duration} --output json')

        result = host.backend.run_local(civ_local_command_to_run)
        assert result.succeeded, \
            f'Failed to obtain temporary AWS credentials. Error: {result.stderr}'

        temporary_creds_json = json.loads(result.stdout)['Credentials']

        temporary_auth_config = {
            'aws_access_key_id': temporary_creds_json['AccessKeyId'],
            'aws_secret_access_key': temporary_creds_json['SecretAccessKey'],
            'aws_session_token': temporary_creds_json['SessionToken'],
        }
        # Export env vars from the local command output, from the host
        for key, value in temporary_auth_config.items():
            result = host.run(f'aws configure set {key} {value}')
            assert result.succeeded, \
                f'Could not configure temporary AWS credentials. Error: {result.stderr}'

    def test_awscli2_version(self, host):
        expected_version_rhel_9 = '2.15.31'
        expected_version_rhel_10 = '2.27.0'

        if version.parse(host.system_info.release).major == 10:
            expected_version = expected_version_rhel_10
        else:
            expected_version = expected_version_rhel_9

        result = test_lib.print_host_command_output(host,
                                                    'aws --version',
                                                    capture_result=True,
                                                    use_sudo=False)

        assert result.succeeded, 'Failed to get AWS version.'
        assert f'aws-cli/{expected_version}' in result.stdout, 'Unexpected aswcli2 version.'

    def test_awscli2_authentication(self, host):
        result = host.run('aws sts get-caller-identity')
        assert result.succeeded, \
            f'Failed to get AWS identity. Error: {result.stderr}'

        identity_found = '"UserId":' in result.stdout and \
                         '"Account":' in result.stdout and \
                         '"Arn":' in result.stdout

        assert identity_found, 'Unexpected identity output.'
        print('Authentication successful!')

    def test_awscli2_basic_query(self, host, instance_data):
        """
        Verify information about the instance where this test is being executed from
        """
        region = instance_data['availability_zone'][:-1]

        # Run a query to get the instance IDs of all running instances
        command_to_run = (f'aws ec2 describe-instances '
                          f'--region {region} '
                          f'--query "Reservations[].Instances[*].InstanceId"')

        result = test_lib.print_host_command_output(host,
                                                    command_to_run,
                                                    capture_result=True,
                                                    use_sudo=False)
        assert result.succeeded, f'Failed to query AWS instances. Error: {result.stderr}'

        # Search for our own instance ID in the output for a sanity check
        instance_id = instance_data['instance_id']
        assert instance_id in result.stdout, \
            f'Expected Instance ID {instance_id} not found in AWS query output.'
