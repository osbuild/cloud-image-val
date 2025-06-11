import os

import yaml


class CIVConfig:
    config_path = 'civ_config.yaml'
    command_line_args = {}

    config_file_arg_name = 'config_file'

    def __init__(self, args_dict: dict = None):
        if args_dict is None:
            return

        if self.config_file_arg_name in args_dict and \
           args_dict[self.config_file_arg_name] is not None:
            self.config_path = args_dict[self.config_file_arg_name]
        elif os.path.exists(self.config_path):
            os.system(f'rm -f {self.config_path}')

        self.command_line_args = args_dict

    def validate_config(self):
        with open(self.config_path) as config_file:
            try:
                config = yaml.safe_load(config_file)
            except Exception as e:
                print('ERROR: Failed to load the config yaml, please check the syntax.')
                print(e)
                exit(1)

            assert 'resources_file' in config.keys(), 'ERROR: Please provide a resources file'
            assert 'output_file' in config.keys(), 'ERROR: Please provide an output path'

    def write_config(self, config_to_write):
        with open(self.config_path, 'w+') as config_file:
            yaml.dump(config_to_write, config_file)

    def update_config(self):
        config = self.get_default_config()

        if os.path.exists(self.config_path):
            config.update(self.get_config())

        self.__override_config_from_cmd_line_arg(config)

        self.write_config(config)

    def __override_config_from_cmd_line_arg(self, config):
        if len(self.command_line_args) == 1 and \
                self.config_file_arg_name in self.command_line_args:
            return

        self.command_line_args.pop(self.config_file_arg_name)

        for arg_name, arg_value in self.command_line_args.items():
            if arg_name not in config:
                config[arg_name] = arg_value

            if arg_value == config[arg_name] or arg_value is None:
                continue

            print(f'Overriding "{arg_name}" config item with command-line argument value...')

            if arg_name == 'tags':
                config[arg_name] = self.get_tags_dict_from_command_line_arg_value(arg_value)
                continue

            config[arg_name] = arg_value

    def get_tags_dict_from_command_line_arg_value(self, tags_arg_value):
        tags_dict = {}

        tags_list = tags_arg_value.split(',')

        for t in tags_list:
            tag_data = t.split(':')
            tags_dict[tag_data[0].strip()] = tag_data[1].strip()

        return tags_dict

    def get_config(self):
        with open(self.config_path) as config_file:
            config = yaml.safe_load(config_file)

        return config

    def get_default_config(self):
        config_defaults = {
            'resources_file': None,
            'output_file': None,
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
            'ssh_config_file': '/tmp/ssh_config'
        }

        return config_defaults

    def export_config_as_env_vars(self):
        config = self.get_config()

        for key in config.keys():
            composed_env_var_name = f'CIV_{key}'.upper()
            os.environ[composed_env_var_name] = self.__get_config_value_as_string(config, key)

    def __get_config_value_as_string(self, config, config_key):
        if config_key not in config:
            raise ValueError(f'Invalid config key. The key "{config_key}" does not exist in current CIV config.')

        config_value = config[config_key]
        if type(config_value) is dict:
            config_value = ','.join([f'{k}={v}' for k, v in config_value.items()])
        elif type(config_value) is list:
            config_value = ','.join(config_value)

        return str(config_value)
