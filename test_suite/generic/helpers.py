import os
import json


def __get_instance_data_from_json(key_to_find, values_to_find):
    with open(os.environ['CIV_INSTANCES_JSON'], 'r') as f:
        instances_json_data = json.load(f)
    for instance in instances_json_data.values():
        if key_to_find in instance.keys() and instance[key_to_find] in values_to_find:
            return instance