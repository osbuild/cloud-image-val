import json
import os

import jsonschema
import pytest


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '..', 'schemas', 'civ-instances.schema.json')


@pytest.fixture
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


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

    def test_schema_is_valid_json_schema(self, schema):
        jsonschema.Draft202012Validator.check_schema(schema)

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
        jsonschema.validate(self.valid_minimal_document, schema)

    def test_valid_full_document(self, schema):
        jsonschema.validate(self.valid_full_document, schema)

    def test_valid_multi_instance(self, schema):
        jsonschema.validate(self.valid_multi_instance_document, schema)

    def test_valid_empty_document(self, schema):
        jsonschema.validate({}, schema)

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
        jsonschema.validate(doc, schema)

    def test_invalid_missing_required_field(self, schema):
        doc = {
            "instance-1": {
                "address": "54.123.45.67",
                "username": "ec2-user",
                "cloud": "aws",
                "image": "RHEL-9.5"
            }
        }
        with pytest.raises(jsonschema.ValidationError, match="'name' is a required property"):
            jsonschema.validate(doc, schema)

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
        with pytest.raises(jsonschema.ValidationError, match="'digitalocean' is not one of"):
            jsonschema.validate(doc, schema)

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
        with pytest.raises(jsonschema.ValidationError, match="is not of type 'string'"):
            jsonschema.validate(doc, schema)

    def test_invalid_top_level_not_object(self, schema):
        with pytest.raises(jsonschema.ValidationError, match="is not of type 'object'"):
            jsonschema.validate(["not", "an", "object"], schema)
