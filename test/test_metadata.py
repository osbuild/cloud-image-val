import json
import os

import jsonschema
import pytest

from core.metadata import (
    InstanceMetadata,
    set_civ_env_vars,
    write_instances_json,
    write_ssh_config,
)


SAMPLE_AWS_OPENTOFU_DICT = {
    'cloud': 'aws',
    'name': 'civ-rhel-95-12345',
    'instance_id': 'i-0abc123def456',
    'public_ip': '54.123.45.67',
    'public_dns': 'ec2-54-123-45-67.us-east-1.compute.amazonaws.com',
    'private_ip': '10.0.1.5',
    'availability_zone': 'us-east-1a',
    'ami': 'ami-0123456789',
    'image': 'RHEL-9.5-x86_64',
    'username': 'ec2-user',
    'address': 'ec2-54-123-45-67.us-east-1.compute.amazonaws.com',
}

SAMPLE_AZURE_OPENTOFU_DICT = {
    'cloud': 'azure',
    'name': 'civ-rhel-95-22222',
    'instance_id': '/subscriptions/.../vm-1',
    'public_ip': '20.1.2.3',
    'private_ip': '10.0.0.4',
    'public_dns': '',
    'location': 'eastus',
    'image': {
        'publisher': 'RedHat',
        'offer': 'RHEL',
        'sku': '95-gen2',
        'version': 'latest',
    },
    'username': 'cloud-user',
    'address': '20.1.2.3',
}

SAMPLE_GCLOUD_OPENTOFU_DICT = {
    'cloud': 'gcloud',
    'name': 'civ-rhel-95-33333',
    'instance_id': '1234567890123456789',
    'public_ip': '35.200.1.1',
    'public_dns': '35.200.1.1',
    'address': '35.200.1.1',
    'zone': 'us-central1-a',
    'image': 'rhel-9-v20240515',
    'username': 'cloud-user',
}

SAMPLE_OCI_OPENTOFU_DICT = {
    'cloud': 'oci',
    'name': 'civ-rhel-95-44444',
    'instance_id': 'ocid1.instance.oc1.iad.abc123',
    'public_ip': '129.213.1.1',
    'public_dns': '129.213.1.1',
    'private_ip': '10.0.0.10',
    'availability_domain': 'AD-1',
    'shape': 'VM.Standard.E4.Flex',
    'image': 'ocid1.image.oc1.iad.xyz789',
    'username': 'opc',
    'address': '129.213.1.1',
}


@pytest.fixture
def aws_instance():
    return InstanceMetadata(
        name='civ-rhel-95-12345',
        address='ec2-54-123-45-67.us-east-1.compute.amazonaws.com',
        username='ec2-user',
        cloud='aws',
        image='RHEL-9.5-x86_64',
    )


@pytest.fixture
def azure_instance():
    return InstanceMetadata(
        name='civ-rhel-95-22222',
        address='20.1.2.3',
        username='cloud-user',
        cloud='azure',
        image={
            'publisher': 'RedHat',
            'offer': 'RHEL',
            'sku': '95-gen2',
            'version': 'latest',
        },
    )


@pytest.fixture
def two_instances(aws_instance):
    second = InstanceMetadata(
        name='civ-rhel-93-67890',
        address='54.200.1.1',
        username='ec2-user',
        cloud='aws',
        image='RHEL-9.3-x86_64',
        region='us-west-2',
    )
    return {
        'aws_instance.civ-rhel-95-12345': aws_instance,
        'aws_instance.civ-rhel-93-67890': second,
    }


@pytest.fixture(autouse=True)
def _clean_civ_env_vars(monkeypatch):
    for key in list(os.environ):
        if key.startswith('CIV_'):
            monkeypatch.delenv(key)
    yield


class TestInstanceMetadata:

    def test_required_fields(self, aws_instance):
        assert aws_instance.name == 'civ-rhel-95-12345'
        assert aws_instance.address == 'ec2-54-123-45-67.us-east-1.compute.amazonaws.com'
        assert aws_instance.username == 'ec2-user'
        assert aws_instance.cloud == 'aws'
        assert aws_instance.image == 'RHEL-9.5-x86_64'

    def test_optional_fields_default_to_empty_string(self):
        inst = InstanceMetadata(
            name='test', address='1.2.3.4', username='user',
            cloud='aws', image='img',
        )
        assert inst.region == ""
        assert inst.distro == ""
        assert inst.version == ""
        assert inst.arch == ""
        assert inst.image_id == ""
        assert inst.instance_type == ""

    def test_optional_fields_can_be_set(self):
        inst = InstanceMetadata(
            name='test', address='1.2.3.4', username='user',
            cloud='aws', image='img',
            region='us-east-1', distro='rhel', version='9.5',
            arch='x86_64', image_id='ami-123', instance_type='t3.medium',
        )
        assert inst.region == 'us-east-1'
        assert inst.arch == 'x86_64'
        assert inst.instance_type == 't3.medium'

    def test_image_can_be_dict(self, azure_instance):
        assert isinstance(azure_instance.image, dict)
        assert azure_instance.image['publisher'] == 'RedHat'

    def test_to_dict_with_dict_image(self, azure_instance):
        d = azure_instance.to_dict()
        assert isinstance(d['image'], dict)
        assert d['image'] == azure_instance.image
        assert d['image']['publisher'] == 'RedHat'

    def test_to_dict_omits_empty_optional_fields(self, aws_instance):
        d = aws_instance.to_dict()
        assert isinstance(d, dict)
        assert d['name'] == 'civ-rhel-95-12345'
        assert d['cloud'] == 'aws'
        assert 'region' not in d
        assert 'arch' not in d

    def test_to_dict_keeps_required_fields_even_if_empty(self):
        inst = InstanceMetadata(
            name='', address='1.2.3.4', username='user',
            cloud='aws', image='img',
        )
        d = inst.to_dict()
        assert 'name' in d
        assert d['name'] == ''

    def test_to_dict_includes_non_empty_optional_fields(self):
        inst = InstanceMetadata(
            name='test', address='1.2.3.4', username='user',
            cloud='aws', image='img', region='us-east-1',
        )
        d = inst.to_dict()
        assert d['region'] == 'us-east-1'
        assert 'arch' not in d

    def test_to_dict_roundtrip(self, aws_instance):
        d = aws_instance.to_dict()
        restored = InstanceMetadata.from_dict(d)
        assert restored == aws_instance


class TestFromDict:

    def test_from_aws_opentofu_dict(self):
        inst = InstanceMetadata.from_dict(SAMPLE_AWS_OPENTOFU_DICT)
        assert inst.name == 'civ-rhel-95-12345'
        assert inst.address == 'ec2-54-123-45-67.us-east-1.compute.amazonaws.com'
        assert inst.username == 'ec2-user'
        assert inst.cloud == 'aws'
        assert inst.image == 'RHEL-9.5-x86_64'

    def test_from_azure_opentofu_dict(self):
        inst = InstanceMetadata.from_dict(SAMPLE_AZURE_OPENTOFU_DICT)
        assert inst.cloud == 'azure'
        assert isinstance(inst.image, dict)
        assert inst.image['publisher'] == 'RedHat'

    def test_from_gcloud_opentofu_dict(self):
        inst = InstanceMetadata.from_dict(SAMPLE_GCLOUD_OPENTOFU_DICT)
        assert inst.cloud == 'gcloud'
        assert inst.name == 'civ-rhel-95-33333'
        assert inst.address == '35.200.1.1'
        assert inst.username == 'cloud-user'
        assert inst.image == 'rhel-9-v20240515'

    def test_from_oci_opentofu_dict(self):
        inst = InstanceMetadata.from_dict(SAMPLE_OCI_OPENTOFU_DICT)
        assert inst.cloud == 'oci'
        assert inst.name == 'civ-rhel-95-44444'
        assert inst.address == '129.213.1.1'
        assert inst.username == 'opc'
        assert inst.image == 'ocid1.image.oc1.iad.xyz789'

    def test_ignores_unknown_keys(self):
        inst = InstanceMetadata.from_dict(SAMPLE_AWS_OPENTOFU_DICT)
        assert not hasattr(inst, 'instance_id')
        assert not hasattr(inst, 'public_ip')
        assert not hasattr(inst, 'ami')
        assert not hasattr(inst, 'availability_zone')

    def test_preserves_optional_fields_when_present(self):
        data = {**SAMPLE_AWS_OPENTOFU_DICT, 'region': 'us-east-1', 'arch': 'x86_64'}
        inst = InstanceMetadata.from_dict(data)
        assert inst.region == 'us-east-1'
        assert inst.arch == 'x86_64'

    def test_missing_required_field_raises_value_error(self):
        incomplete = {'name': 'test', 'address': '1.2.3.4'}
        with pytest.raises(ValueError, match="Missing required field"):
            InstanceMetadata.from_dict(incomplete)

    def test_wrong_type_for_name_raises_type_error(self):
        data = {**SAMPLE_AWS_OPENTOFU_DICT, 'name': 123}
        with pytest.raises(TypeError, match="Field 'name' must be str"):
            InstanceMetadata.from_dict(data)

    def test_wrong_type_for_image_raises_type_error(self):
        data = {**SAMPLE_AWS_OPENTOFU_DICT, 'image': 123}
        with pytest.raises(TypeError, match="Field 'image' must be str or dict"):
            InstanceMetadata.from_dict(data)

    def test_none_value_for_required_field_raises_type_error(self):
        data = {**SAMPLE_AWS_OPENTOFU_DICT, 'address': None}
        with pytest.raises(TypeError, match="Field 'address' must be str"):
            InstanceMetadata.from_dict(data)

    def test_wrong_type_for_optional_field_raises_type_error(self):
        data = {**SAMPLE_AWS_OPENTOFU_DICT, 'region': 123}
        with pytest.raises(TypeError, match="Field 'region' must be str"):
            InstanceMetadata.from_dict(data)


class TestWriteInstancesJson:

    def test_writes_valid_json(self, tmp_path, aws_instance):
        path = str(tmp_path / 'instances.json')
        instances = {'aws_instance.test': aws_instance}

        write_instances_json(instances, path)

        with open(path) as f:
            data = json.load(f)
        assert 'aws_instance.test' in data
        assert data['aws_instance.test']['name'] == 'civ-rhel-95-12345'

    def test_output_validates_against_schema(self, tmp_path, aws_instance, azure_instance):
        path = str(tmp_path / 'instances.json')
        instances = {
            'aws_instance.test': aws_instance,
            'azure_instance.test': azure_instance,
        }

        write_instances_json(instances, path)

        schema_path = os.path.join(
            os.path.dirname(__file__), '..', 'schemas', 'civ-instances.schema.json',
        )
        with open(schema_path) as f:
            schema = json.load(f)
        with open(path) as f:
            document = json.load(f)
        jsonschema.validate(document, schema)

    def test_invalid_data_raises_validation_error(self, tmp_path):
        path = str(tmp_path / 'instances.json')
        bad_instance = InstanceMetadata(
            name='test', address='1.2.3.4', username='user',
            cloud='digitalocean', image='img',
        )
        with pytest.raises(jsonschema.ValidationError):
            write_instances_json({'key': bad_instance}, path)

    def test_json_is_indented(self, tmp_path, aws_instance):
        path = str(tmp_path / 'instances.json')
        write_instances_json({'key': aws_instance}, path)

        with open(path) as f:
            raw = f.read()
        assert '    ' in raw

    def test_empty_instances(self, tmp_path):
        path = str(tmp_path / 'instances.json')
        write_instances_json({}, path)

        with open(path) as f:
            data = json.load(f)
        assert data == {}


class TestWriteSshConfig:

    def test_creates_config_file(self, tmp_path, aws_instance):
        config_path = str(tmp_path / 'ssh_config')
        instances = {'aws_instance.test': aws_instance}

        write_ssh_config(instances, '/path/to/key', config_path)

        assert os.path.exists(config_path)

    def test_config_contains_host_entry(self, tmp_path, aws_instance):
        config_path = str(tmp_path / 'ssh_config')
        instances = {'aws_instance.test': aws_instance}

        write_ssh_config(instances, '/path/to/key', config_path)

        with open(config_path) as f:
            content = f.read()
        assert 'Host ec2-54-123-45-67.us-east-1.compute.amazonaws.com' in content

    def test_config_contains_expected_parameters(self, tmp_path, aws_instance):
        config_path = str(tmp_path / 'ssh_config')
        write_ssh_config({'key': aws_instance}, '/path/to/key', config_path)

        with open(config_path) as f:
            content = f.read()
        assert 'User ec2-user' in content
        assert 'IdentityFile /path/to/key' in content
        assert 'Port 22' in content
        assert 'StrictHostKeyChecking no' in content
        assert 'UserKnownHostsFile /dev/null' in content
        assert 'LogLevel ERROR' in content
        assert 'ConnectTimeout 30' in content
        assert 'ConnectionAttempts 5' in content

    def test_multiple_instances(self, tmp_path, two_instances):
        config_path = str(tmp_path / 'ssh_config')
        write_ssh_config(two_instances, '/path/to/key', config_path)

        with open(config_path) as f:
            content = f.read()
        assert content.count('Host ') == 2

    def test_overwrites_existing_file(self, tmp_path, aws_instance):
        config_path = str(tmp_path / 'ssh_config')
        with open(config_path, 'w') as f:
            f.write('old content')

        write_ssh_config({'key': aws_instance}, '/path/to/key', config_path)

        with open(config_path) as f:
            content = f.read()
        assert 'old content' not in content
        assert 'Host' in content


class TestSetCivEnvVars:

    def test_sets_expected_env_vars(self, aws_instance):
        instances = {'aws_instance.test': aws_instance}

        set_civ_env_vars(instances, '/tmp/instances.json', '/tmp/ssh_config')

        assert os.environ['CIV_CLOUD'] == 'aws'
        assert os.environ['CIV_INSTANCES_JSON'] == '/tmp/instances.json'
        assert os.environ['CIV_INSTANCES_COUNT'] == '1'
        assert os.environ['CIV_SSH_CONFIG'] == '/tmp/ssh_config'

    def test_count_reflects_instance_count(self, two_instances):
        set_civ_env_vars(two_instances, '/tmp/instances.json', '/tmp/ssh_config')

        assert os.environ['CIV_INSTANCES_COUNT'] == '2'

    def test_empty_instances(self):
        set_civ_env_vars({}, '/tmp/instances.json', '/tmp/ssh_config')

        assert os.environ['CIV_CLOUD'] == ''
        assert os.environ['CIV_INSTANCES_COUNT'] == '0'

    def test_mixed_clouds_raises_value_error(self, aws_instance):
        azure = InstanceMetadata(
            name='civ-rhel-95-22222', address='20.1.2.3',
            username='cloud-user', cloud='azure', image='img',
        )
        instances = {
            'aws': aws_instance,
            'azure': azure,
        }
        with pytest.raises(ValueError, match="All instances must share the same cloud"):
            set_civ_env_vars(instances, '/tmp/instances.json', '/tmp/ssh_config')

    def test_sets_exactly_four_civ_vars(self, aws_instance):
        set_civ_env_vars(
            {'aws_instance.test': aws_instance},
            '/tmp/instances.json',
            '/tmp/ssh_config',
        )

        civ_vars = {k for k in os.environ if k.startswith('CIV_')}
        assert civ_vars == {'CIV_CLOUD', 'CIV_INSTANCES_JSON', 'CIV_INSTANCES_COUNT', 'CIV_SSH_CONFIG'}
