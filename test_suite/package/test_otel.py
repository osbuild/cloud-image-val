import pytest
import logging

logger = logging.getLogger(__name__)

package_name = 'opentelemetry-collector-cloudwatch-config'
@pytest.fixture()
def modify_iam_role(request):
    instance_id = instance_data['instance_id']
    iam_role_name = "CloudWatchAgentServerRole_2"

    modify_iam_role_cmd = (f"aws ec2 associate-iam-instance-profile "
                           f"--instance-id {instance_id}"
                           f"--iam-instance-profile Name={iam_role_name}")

    assert host.run_test(modify_iam_role_cmd), 'faild to update iam role'


@pytest.fixture()
def install_packages(request):
    install_cmd = f'yum install -y  {package_name}'
    assert host.run_test(install_cmd), f'Failed to install the package {package_name}'

@pytest.fixture()
def start_service(request):
    start_enable_service = (f'systemctl start {package_name} && systemctl enable {package_name}')
    is_active = (f'systemctl is-active {package_name}')
    with host.sudo():
        assert host.run_test(start_enable_service), (f'Failed to start the service {package_name}')
        assert host.run_test(is_active), (f'Failed to activate the service {package_name}')


@pytest.mark.package
class TestOtel:

    @pytest.mark.usefixtures(
        modify_iam_role.__name__,
        install_packages.__name__,
        start_service.__name__,
    )
    def test_otel(self, host, instance_data):

        logger.info("Connect to the instance without a key in order to fail")
        instance_dns = instance_data['public_dns']
        assert not host.run_test(f'ssh {instance_dns}')
        # TODO: verification for the error logs