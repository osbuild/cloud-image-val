import os
import json
from lib import test_lib

INSTANCES_JSON_PATH = os.environ['CIV_INSTANCES_JSON']


def __get_instance_data_from_json(key_to_find, values_to_find, path=INSTANCES_JSON_PATH):
    with open(path, 'r') as f:
        instances_json_data = json.load(f)
    for instance in instances_json_data.values():
        if key_to_find in instance.keys() and instance[key_to_find] in values_to_find:
            return instance


def check_avc_denials(host):
    command_to_run = 'x=$(ausearch -m avc 2>&1 &); echo $x'
    result = test_lib.print_host_command_output(host,
                                                command_to_run,
                                                capture_result=True)

    no_avc_denials_found = 'no matches' in result.stdout

    # ignore avc denial for irqbalance
    # remove when RHEL-78630 is fixed
    if 'irqbalance' in result.stdout:
        no_avc_denials_found = True

    assert no_avc_denials_found, 'There should not be any avc denials (selinux)'
