import yaml


class CIVConfig():
    def __init__(self, config_path='/tmp/civ_config.yml'):
        self.config_path = config_path

    def validate(self):
        with open(self.config_path) as config_file:
            try:
                config = yaml.safe_load(config_file)
            except Exception as e:
                print(f'ERROR: loading the config yaml failed, please check the sintax.\n{e}')
                exit()

            assert 'resources_file' in config.keys(), 'ERROR: Please provide a resources file'
            assert 'output_file' in config.keys(), 'ERROR: Please provide an output path'

        self.set_defaults(config)

    def write_config(self, args):
        args = args.__dict__
        with open(self.config_path, 'w+') as config_file:
            yaml.dump(args, config_file)

    def get_config(self):
        with open(self.config_path) as config_file:
            config = yaml.safe_load(config_file)

        return config

    def set_defaults(self, config):
        config_defaults = {'environment': 'local',
                           'tags': None,
                           'debug': False,
                           'include_markers': None,
                           'parallel': False,
                           'stop_cleanup': False,
                           'test_filter': None}

        for default in config_defaults:
            if default not in config:
                config[default] = config_defaults[default]

        with open(self.config_path, 'w+') as config_file:
            yaml.dump(config, config_file)
