import json
import os
import subprocess

import pytest


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '..', 'schemas', 'civ-instances.schema.json')


@pytest.fixture
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def validate(document, schema):
    """Validate a document against the schema using python -m jsonschema if available, else basic checks."""
    doc_json = json.dumps(document)
    schema_json = json.dumps(schema)

    script = (
        "import json, sys; "
        "doc = json.loads(sys.argv[1]); "
        "schema = json.loads(sys.argv[2]); "
        "from jsonschema import validate, ValidationError; "
        "validate(doc, schema)"
    )
    result = subprocess.run(
        ['python3', '-c', script, doc_json, schema_json],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise ValueError(result.stderr)


def validate_expect_failure(document, schema, match):
    """Assert that validation fails with an error matching the given string."""
    with pytest.raises(ValueError, match=match):
        validate(document, schema)


class TestCivInstancesSchema:

    valid_minimal_document = {
        "aws_instance.civ-rhel-95-12345": {
            "name": "civ-rhel-95-12345",
            "address": "ec2-54-123-45-67.us-east-1.compute.amazonaws.com",
            "username": "ec2-user",
            "cloud": "aws",
            "image": "RHEL-9.5-x86_64"
        }
    }

    valid_full_document = {
        "aws_instance.civ-rhel-93-us-east-1": {
            "name": "rhel-9.3-aws-us-east-1",
            "address": "54.123.45.67",
            "username": "ec2-user",
            "cloud": "aws",
            "region": "us-east-1",
            "distro": "rhel",
            "version": "9.3",
            "arch": "x86_64",
            "image_id": "ami-0123456789",
            "instance_type": "t3.medium",
            "image": "RHEL-9.3-x86_64",
            "instance_id": "i-0abc123def456",
            "public_ip": "54.123.45.67",
            "public_dns": "ec2-54-123-45-67.us-east-1.compute.amazonaws.com",
            "private_ip": "10.0.1.5",
            "availability_zone": "us-east-1a",
            "ami": "ami-0123456789"
        }
    }

    valid_multi_instance_document = {
        "aws_instance.civ-rhel-95-11111": {
            "name": "civ-rhel-95-11111",
            "address": "54.1.2.3",
            "username": "ec2-user",
            "cloud": "aws",
            "image": "RHEL-9.5-x86_64"
        },
        "azurerm_linux_virtual_machine.civ-rhel-95-22222": {
            "name": "civ-rhel-95-22222",
            "address": "20.1.2.3",
            "username": "cloud-user",
            "cloud": "azure",
            "image": {
                "publisher": "RedHat",
                "offer": "RHEL",
                "sku": "95-gen2",
                "version": "latest"
            }
        }
    }

    def test_schema_is_valid_json(self, schema):
        assert schema.get('$schema') is not None
        assert schema.get('type') == 'object'
        assert '$defs' in schema
        assert 'instance' in schema['$defs']

    def test_schema_required_fields(self, schema):
        instance_def = schema['$defs']['instance']
        assert set(instance_def['required']) == {'name', 'address', 'username', 'cloud', 'image'}

    def test_schema_optional_fields(self, schema):
        instance_props = schema['$defs']['instance']['properties']
        for field in ('region', 'distro', 'version', 'arch', 'image_id', 'instance_type'):
            assert field in instance_props, f"Optional field '{field}' missing from schema"

    def test_schema_field_descriptions(self, schema):
        instance_props = schema['$defs']['instance']['properties']
        for field_name, field_def in instance_props.items():
            assert 'description' in field_def, f"Field '{field_name}' missing description"

    def test_valid_minimal_document(self, schema):
        validate(self.valid_minimal_document, schema)

    def test_valid_full_document(self, schema):
        validate(self.valid_full_document, schema)

    def test_valid_multi_instance(self, schema):
        validate(self.valid_multi_instance_document, schema)

    def test_valid_empty_document(self, schema):
        validate({}, schema)

    def test_valid_azure_image_as_object(self, schema):
        doc = {
            "azurerm_linux_virtual_machine.civ-vm-1": {
                "name": "civ-vm-1",
                "address": "20.1.2.3",
                "username": "cloud-user",
                "cloud": "azure",
                "image": {"publisher": "RedHat", "offer": "RHEL", "sku": "9", "version": "latest"}
            }
        }
        validate(doc, schema)

    def test_invalid_missing_required_field(self, schema):
        doc = {
            "instance-1": {
                "address": "54.123.45.67",
                "username": "ec2-user",
                "cloud": "aws",
                "image": "RHEL-9.5"
            }
        }
        validate_expect_failure(doc, schema, "required property")

    def test_invalid_cloud_value(self, schema):
        doc = {
            "instance-1": {
                "name": "test",
                "address": "1.2.3.4",
                "username": "ec2-user",
                "cloud": "digitalocean",
                "image": "RHEL-9.5"
            }
        }
        validate_expect_failure(doc, schema, "is not one of")

    def test_invalid_name_type(self, schema):
        doc = {
            "instance-1": {
                "name": 123,
                "address": "1.2.3.4",
                "username": "ec2-user",
                "cloud": "aws",
                "image": "RHEL-9.5"
            }
        }
        validate_expect_failure(doc, schema, "is not of type")

    def test_invalid_top_level_not_object(self, schema):
        validate_expect_failure(["not", "an", "object"], schema, "is not of type")
