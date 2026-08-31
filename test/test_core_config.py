import pytest
import yaml

from core.config import CoreConfig


MINIMAL_VALID = {
    'resources_file': 'resources.json',
    'output_file': 'report.xml',
}

FULL_VALID = {
    'resources_file': 'resources.json',
    'output_file': 'report.xml',
    'environment': 'automated',
    'tags': {'team': 'cloudx', 'env': 'staging'},
    'debug': True,
    'parallel': True,
    'stop_cleanup': True,
    'instances_json': '/var/run/civ/instances.json',
    'ssh_identity_file': '/var/run/civ/ssh-key',
    'ssh_pub_key_file': '/var/run/civ/ssh-key.pub',
    'ssh_config_file': '/var/run/civ/ssh-config',
    'test_filter': 'test_selinux',
    'test_suites': ['generic', 'cloud'],
    'include_markers': 'not pub',
}

LEGACY_CONFIG = {
    'resources_file': '/path/to/resources.json',
    'output_file': '/path/to/output.xml',
    'environment': 'local',
    'tags': None,
    'debug': False,
    'include_markers': None,
    'parallel': False,
    'stop_cleanup': None,
    'test_filter': None,
    'test_suites': None,
    'instances_json': '/tmp/instances.json',
    'ssh_identity_file': '/tmp/ssh_key',
    'ssh_pub_key_file': '/tmp/ssh_key.pub',
    'ssh_config_file': '/tmp/ssh_config',
}


class TestCoreConfigDefaults:

    def test_minimal_construction(self):
        cfg = CoreConfig(resources_file='res.json', output_file='out.xml')
        assert cfg.resources_file == 'res.json'
        assert cfg.output_file == 'out.xml'

    def test_default_values(self):
        cfg = CoreConfig(resources_file='res.json', output_file='out.xml')
        assert cfg.environment == 'local'
        assert cfg.tags is None
        assert cfg.debug is False
        assert cfg.parallel is False
        assert cfg.stop_cleanup is False
        assert cfg.instances_json == '/tmp/civ-instances.json'
        assert cfg.ssh_identity_file == '/tmp/civ-ssh-key'
        assert cfg.ssh_pub_key_file == '/tmp/civ-ssh-key.pub'
        assert cfg.ssh_config_file == '/tmp/civ-ssh-config'
        assert cfg.test_filter is None
        assert cfg.test_suites is None
        assert cfg.include_markers is None

    def test_all_fields_have_type_hints(self):
        annotations = CoreConfig.__annotations__
        assert 'resources_file' in annotations
        assert 'output_file' in annotations
        assert 'environment' in annotations
        assert 'tags' in annotations
        assert 'debug' in annotations
        assert 'parallel' in annotations
        assert 'stop_cleanup' in annotations
        assert 'instances_json' in annotations
        assert 'ssh_identity_file' in annotations
        assert 'ssh_pub_key_file' in annotations
        assert 'ssh_config_file' in annotations
        assert 'test_filter' in annotations
        assert 'test_suites' in annotations
        assert 'include_markers' in annotations


class TestValidation:

    def test_missing_resources_file_raises(self):
        with pytest.raises(ValueError, match="'resources_file' is required"):
            CoreConfig(resources_file='', output_file='out.xml')

    def test_missing_output_file_raises(self):
        with pytest.raises(ValueError, match="'output_file' is required"):
            CoreConfig(resources_file='res.json', output_file='')

    def test_whitespace_only_required_field_raises(self):
        with pytest.raises(ValueError, match="'resources_file' is required"):
            CoreConfig(resources_file='   ', output_file='out.xml')

    def test_invalid_environment_raises(self):
        with pytest.raises(ValueError, match="'environment' must be one of"):
            CoreConfig(
                resources_file='res.json',
                output_file='out.xml',
                environment='staging',
            )

    def test_valid_environments(self):
        for env in ('local', 'automated'):
            cfg = CoreConfig(
                resources_file='res.json', output_file='out.xml', environment=env,
            )
            assert cfg.environment == env

    def test_invalid_tags_type_raises(self):
        with pytest.raises(ValueError, match="'tags' must be a dict or None"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml', tags='bad',
            )

    def test_invalid_test_suites_type_raises(self):
        with pytest.raises(ValueError, match="'test_suites' must be a list or None"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml', test_suites='bad',
            )

    def test_non_string_required_field_raises(self):
        with pytest.raises(ValueError, match="'resources_file' is required"):
            CoreConfig(resources_file=123, output_file='out.xml')

    def test_non_string_path_field_raises(self):
        with pytest.raises(ValueError, match="'instances_json' must be a string"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml', instances_json=42,
            )

    def test_non_bool_debug_raises(self):
        with pytest.raises(ValueError, match="'debug' must be a bool"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml', debug='yes',
            )

    def test_non_bool_parallel_raises(self):
        with pytest.raises(ValueError, match="'parallel' must be a bool"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml', parallel=1,
            )

    def test_non_bool_stop_cleanup_raises(self):
        with pytest.raises(ValueError, match="'stop_cleanup' must be a bool"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml', stop_cleanup='no',
            )

    def test_non_string_tag_value_raises(self):
        with pytest.raises(ValueError, match="'tags' keys and values must be strings"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml',
                tags={'key': 123},
            )

    def test_non_string_tag_key_raises(self):
        with pytest.raises(ValueError, match="'tags' keys and values must be strings"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml',
                tags={42: 'value'},
            )

    def test_non_string_test_suites_element_raises(self):
        with pytest.raises(ValueError, match="'test_suites\\[0\\]' must be a string"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml',
                test_suites=[123],
            )

    def test_list_environment_raises_value_error(self):
        with pytest.raises(ValueError, match="'environment' must be one of"):
            CoreConfig(
                resources_file='res.json', output_file='out.xml',
                environment=['local'],
            )

    def test_validate_can_be_called_explicitly(self):
        cfg = CoreConfig(resources_file='res.json', output_file='out.xml')
        cfg.validate()


class TestToDict:

    def test_returns_dict(self):
        cfg = CoreConfig(resources_file='res.json', output_file='out.xml')
        d = cfg.to_dict()
        assert isinstance(d, dict)

    def test_contains_all_fields(self):
        cfg = CoreConfig(resources_file='res.json', output_file='out.xml')
        d = cfg.to_dict()
        assert d['resources_file'] == 'res.json'
        assert d['output_file'] == 'out.xml'
        assert d['environment'] == 'local'
        assert d['tags'] is None
        assert d['debug'] is False
        assert d['stop_cleanup'] is False

    def test_full_config_roundtrip(self):
        cfg = CoreConfig(**FULL_VALID)
        d = cfg.to_dict()
        assert d['tags'] == {'team': 'cloudx', 'env': 'staging'}
        assert d['test_suites'] == ['generic', 'cloud']
        assert d['debug'] is True
        assert d['parallel'] is True

    def test_roundtrip_from_dict_to_dict(self):
        cfg = CoreConfig.from_dict(FULL_VALID)
        d = cfg.to_dict()
        restored = CoreConfig.from_dict(d)
        assert restored == cfg


class TestFromDict:

    def test_minimal_dict(self):
        cfg = CoreConfig.from_dict(MINIMAL_VALID)
        assert cfg.resources_file == 'resources.json'
        assert cfg.output_file == 'report.xml'
        assert cfg.environment == 'local'

    def test_full_dict(self):
        cfg = CoreConfig.from_dict(FULL_VALID)
        assert cfg.environment == 'automated'
        assert cfg.tags == {'team': 'cloudx', 'env': 'staging'}
        assert cfg.debug is True
        assert cfg.test_filter == 'test_selinux'
        assert cfg.test_suites == ['generic', 'cloud']

    def test_missing_resources_file_raises(self):
        with pytest.raises(ValueError, match="'resources_file' is required"):
            CoreConfig.from_dict({'output_file': 'out.xml'})

    def test_missing_output_file_raises(self):
        with pytest.raises(ValueError, match="'output_file' is required"):
            CoreConfig.from_dict({'resources_file': 'res.json'})

    def test_none_resources_file_raises(self):
        with pytest.raises(ValueError, match="'resources_file' is required"):
            CoreConfig.from_dict({'resources_file': None, 'output_file': 'out.xml'})

    def test_ignores_unknown_keys(self):
        data = {**MINIMAL_VALID, 'unknown_key': 'value', 'another': 42}
        cfg = CoreConfig.from_dict(data)
        assert cfg.resources_file == 'resources.json'
        assert not hasattr(cfg, 'unknown_key')

    def test_legacy_config_format(self):
        cfg = CoreConfig.from_dict(LEGACY_CONFIG)
        assert cfg.resources_file == '/path/to/resources.json'
        assert cfg.output_file == '/path/to/output.xml'
        assert cfg.stop_cleanup is False
        assert cfg.instances_json == '/tmp/instances.json'
        assert cfg.ssh_identity_file == '/tmp/ssh_key'

    def test_stop_cleanup_none_coerced_to_false(self):
        data = {**MINIMAL_VALID, 'stop_cleanup': None}
        cfg = CoreConfig.from_dict(data)
        assert cfg.stop_cleanup is False

    def test_stop_cleanup_true_preserved(self):
        data = {**MINIMAL_VALID, 'stop_cleanup': True}
        cfg = CoreConfig.from_dict(data)
        assert cfg.stop_cleanup is True

    def test_non_dict_input_raises(self):
        with pytest.raises(ValueError, match="Expected a dict"):
            CoreConfig.from_dict(['resources_file', 'output_file'])

    def test_scalar_input_raises(self):
        with pytest.raises(ValueError, match="Expected a dict"):
            CoreConfig.from_dict("not a dict")


class TestFromYaml:

    def test_loads_valid_yaml(self, tmp_path):
        config_file = tmp_path / 'config.yaml'
        config_file.write_text(yaml.dump(MINIMAL_VALID))

        cfg = CoreConfig.from_yaml(str(config_file))

        assert cfg.resources_file == 'resources.json'
        assert cfg.output_file == 'report.xml'

    def test_loads_full_yaml(self, tmp_path):
        config_file = tmp_path / 'config.yaml'
        config_file.write_text(yaml.dump(FULL_VALID))

        cfg = CoreConfig.from_yaml(str(config_file))

        assert cfg.environment == 'automated'
        assert cfg.tags == {'team': 'cloudx', 'env': 'staging'}
        assert cfg.test_suites == ['generic', 'cloud']

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            CoreConfig.from_yaml('/nonexistent/config.yaml')

    def test_invalid_yaml_raises(self, tmp_path):
        config_file = tmp_path / 'bad.yaml'
        config_file.write_text(':\n  :\n    - [invalid')

        with pytest.raises(ValueError, match="Failed to parse YAML"):
            CoreConfig.from_yaml(str(config_file))

    def test_non_mapping_yaml_raises(self, tmp_path):
        config_file = tmp_path / 'list.yaml'
        config_file.write_text('- item1\n- item2\n')

        with pytest.raises(ValueError, match="must contain a YAML mapping"):
            CoreConfig.from_yaml(str(config_file))

    def test_missing_required_field_raises(self, tmp_path):
        config_file = tmp_path / 'incomplete.yaml'
        config_file.write_text(yaml.dump({'environment': 'local'}))

        with pytest.raises(ValueError, match="is required"):
            CoreConfig.from_yaml(str(config_file))

    def test_yaml_with_legacy_none_values(self, tmp_path):
        config_file = tmp_path / 'legacy.yaml'
        config_file.write_text(yaml.dump(LEGACY_CONFIG))

        cfg = CoreConfig.from_yaml(str(config_file))

        assert cfg.stop_cleanup is False
        assert cfg.tags is None

    def test_yaml_with_extra_keys(self, tmp_path):
        data = {**MINIMAL_VALID, 'config_file': '/path/to/config.yaml'}
        config_file = tmp_path / 'extra.yaml'
        config_file.write_text(yaml.dump(data))

        cfg = CoreConfig.from_yaml(str(config_file))

        assert cfg.resources_file == 'resources.json'


class TestNoOsSystem:

    def test_module_does_not_use_os_system(self):
        import inspect
        import core.config as config_module

        source = inspect.getsource(config_module)
        assert 'os.system' not in source
