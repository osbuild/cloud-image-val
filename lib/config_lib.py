import os

import yaml


class CIVConfig:
    config_path = 'civ_config.yaml'
    command_line_args = {}

    config_file_arg_name = 'config_file'

    def __init__(self, args=None):
        if args and args.config_file:
            self.config_path = args.config_file

        self.command_line_args = args.__dict__

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
        if os.path.exists(self.config_path):
            config = self.get_config()
        else:
            config = self.get_default_config()

        if len(self.command_line_args) == 1 and self.config_file_arg_name in self.command_line_args:
            return

        self.command_line_args.pop(self.config_file_arg_name)

        for arg_name, arg_value in self.command_line_args.items():
            if arg_name not in config:
                config[arg_name] = arg_value

            if arg_value == config[arg_name] or arg_value is None:
                continue

            print(f'DEBUG: Overriding "{arg_name}" config item...')

            if arg_name == 'tags':
                config[arg_name] = self.get_tags_dict_from_command_line_arg_value(arg_value)
                continue

            config[arg_name] = arg_value

        self.write_config(config)

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
        }

        return config_defaults
