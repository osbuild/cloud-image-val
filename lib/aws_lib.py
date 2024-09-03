import json


def get_aws_instance_identity_from_web(host):
    instance_document_url = 'http://169.254.169.254/latest/dynamic/instance-identity/document'
    return json.loads(host.check_output(f'curl -s {instance_document_url}'))


def is_rhel_aws_stratosphere(host):
    instance_data = get_aws_instance_identity_from_web(host)

    return instance_data['billingProducts'] is None
