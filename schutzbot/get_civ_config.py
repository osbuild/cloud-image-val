"""
Advanced CI test selection logic for cloud-image-val:
- If ONLY specific test methods in a cloud test file are changed, run only those methods for that cloud.
- If ONLY specific test methods in a generic test file are changed, run only those methods for all clouds.
- If any other files or logic are changed (including fixtures, helpers, or CI scripts), run all tests for all clouds.
"""

import os
import re
import subprocess
import sys
import yaml
from pprint import pprint

# Define test file locations
CLOUD_TEST_FILES = {
    'aws': 'test_suite/cloud/test_aws.py',
    'azure': 'test_suite/cloud/test_azure.py',
    'gcp': 'test_suite/cloud/test_gcp.py',
}
GENERIC_TEST_FILE = 'test_suite/generic/test_generic.py'


def get_files_changed():
    try:
        # Use subprocess.run to fetch the upstream main branch
        subprocess.run('git remote add upstream https://github.com/osbuild/cloud-image-val.git', shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run('git fetch upstream', shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Git command failed during setup: {e.stderr.decode()}")
        exit(1)

    files_changed_cmd = ['git', 'diff', '--name-only', 'HEAD', 'upstream/main']
    try:
        files_changed_raw = subprocess.run(
            files_changed_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"ERROR: git diff command failed with status {e.returncode}")
        print(f"stderr: {e.stderr}")
        exit(1)

    files_changed_list = [f.strip() for f in files_changed_raw.stdout.splitlines() if f.strip()]

    if not files_changed_list:
        print('INFO: No changes detected. Proceeding with a full test run.')
        # Return a special list to signify a full run is needed.
        return ['_FULL_RUN_TRIGGER_']

    return files_changed_list


def get_method_changes_for_file(test_file):
    """
    Analyzes the git diff for a specific file to find changed test methods,
    including modifications within existing methods.
    Returns a set of method names that were affected by changes.
    """
    try:
        # Use -U10000 to get a large context, which is necessary to reliably
        # find the function definition enclosing a changed line.
        diff_cmd = ['git', 'diff', '-U10000', 'HEAD', 'upstream/main', '--', test_file]

        diff_output = subprocess.run(
            diff_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )

    except subprocess.CalledProcessError:
        return set()

    diff_lines = diff_output.stdout.splitlines()
    changed_methods = set()
    # Regex to capture method definitions.
    method_pattern = re.compile(r'^\s*def\s+(test_\w+)\s*\(.*?\):')

    for i, line in enumerate(diff_lines):
        # Check for added or removed lines.
        if line.startswith('+') or line.startswith('-'):
            # This is a line that has been changed. Now, we need to find its parent method.
            # We search backwards from the changed line to find the most recent 'def' line.
            for j in range(i, -1, -1):
                clean_line = diff_lines[j].lstrip('+- ').strip()
                match = method_pattern.match(clean_line)
                if match:
                    # We found the enclosing method. Add it to the set and break.
                    changed_methods.add(match.group(1))
                    break

    return changed_methods


def detect_if_only_specific_methods_changed(files_changed):
    """
    Determines if changes are limited to specific test methods within cloud
    or generic test files, or if a broader change requires a full test run.
    Returns a dictionary with 'mode' and 'trigger_files' for auditability.
    """
    cloud_methods = {cloud: set() for cloud in CLOUD_TEST_FILES}
    generic_methods = set()
    trigger_files = []

    for f in files_changed:
        # Check for files that trigger a 'full' mode run
        if f not in CLOUD_TEST_FILES.values() and f != GENERIC_TEST_FILE:
            trigger_files.append(f)
            # Continue processing to collect all trigger files
            continue

        changed_methods = get_method_changes_for_file(f)

        # If a test file is changed but no methods are detected, it's a full file change
        if not changed_methods:
            trigger_files.append(f)
            # Continue processing to collect all trigger files
            continue

        # If a cloud test file is changed with specific methods
        if f in CLOUD_TEST_FILES.values():
            for cloud, path in CLOUD_TEST_FILES.items():
                if f == path:
                    cloud_methods[cloud] = changed_methods

        # If the generic test file is changed with specific methods
        elif f == GENERIC_TEST_FILE:
            generic_methods = changed_methods

    # If any files triggered a full run, return early with the list
    if trigger_files:
        return {
            'mode': 'full',
            'reason': 'Broad changes detected',
            'trigger_files': trigger_files
        }

    # Analyze the results for targeted runs
    impacted_clouds = [cloud for cloud, methods in cloud_methods.items() if methods]

    if impacted_clouds and not generic_methods:
        # Case 1: Only specific methods in a cloud file were changed.
        return {
            'mode': 'cloud_methods',
            'clouds': impacted_clouds,
            'methods': {cloud: cloud_methods[cloud] for cloud in impacted_clouds}
        }

    if generic_methods and not any(cloud_methods.values()):
        # Case 2: Only specific methods in the generic file were changed.
        return {
            'mode': 'generic_methods',
            'clouds': list(CLOUD_TEST_FILES.keys()),
            'methods': {'generic': generic_methods}
        }

    # Case 3: Fallback for other scenarios, including no changes or a mix of cloud/generic method changes
    return {'mode': 'full', 'reason': 'No specific method changes or mixed changes detected', 'trigger_files': []}


def write_vars_file(vars, vars_file_path):
    with open(vars_file_path, 'w+') as vars_file:
        for var in vars:
            if vars[var] is not None:
                vars_file.write(f'export {var}="{vars[var]}"\n')


def write_config_file(config_path, civ_config):
    with open(config_path, 'w+') as config_file:
        yaml.dump(civ_config, config_file)


if __name__ == '__main__':
    vars_file_path = sys.argv[1]
    vars = {}

    # Always run all tests for main branch or CI scripts
    if os.environ['CI_COMMIT_REF_SLUG'] == 'main' or os.getenv('FORCE_FULL_CI', 'false').lower() == 'true':
        run_mode = {'mode': 'full'}
    else:
        files_changed = get_files_changed()
        run_mode = detect_if_only_specific_methods_changed(files_changed)

    civ_config = {'resources_file': '/tmp/resource-file.json',
                  'output_file': '/tmp/report.xml',
                  'environment': 'automated',
                  'tags': {'Workload': 'CI Runner',
                           'Job_name': 'In_CI_Cloud_Test:' + os.environ['CI_JOB_NAME'],
                           'Project': 'CIV',
                           'Branch': os.environ['CI_COMMIT_REF_SLUG'],
                           'Pipeline_id': os.environ['CI_PIPELINE_ID'],
                           'Pipeline_source': os.environ['CI_PIPELINE_SOURCE']},
                  'debug': True,
                  'include_markers': 'not pub'}

    if run_mode['mode'] == 'full':
        # Run all clouds and all tests
        vars['SKIP_AWS'] = 'false'
        vars['SKIP_AZURE'] = 'false'
        vars['SKIP_GCP'] = 'false'
        civ_config['test_filter'] = ''
    elif run_mode['mode'] == 'cloud_methods':
        # Only run impacted clouds and collect all changed methods
        all_methods = set()
        for cloud in CLOUD_TEST_FILES:
            if cloud in run_mode['clouds']:
                vars[f'SKIP_{cloud.upper()}'] = 'false'
                all_methods.update(run_mode['methods'][cloud])
            else:
                vars[f'SKIP_{cloud.upper()}'] = 'true'

        # Build the final pytest filter from all collected methods
        civ_config['test_filter'] = ' or '.join(all_methods)

    elif run_mode['mode'] == 'generic_methods':
        # Run all clouds, but only the changed generic methods
        vars['SKIP_AWS'] = 'false'
        vars['SKIP_AZURE'] = 'false'
        vars['SKIP_GCP'] = 'false'
        civ_config['test_filter'] = ' or '.join(run_mode['methods']['generic'])

    # Additional config from env vars
    if os.getenv("CLOUDX_PKG_TESTING", "false").lower() == "true":
        if 'CUSTOM_PACKAGES' in os.environ:
            civ_config['tags']['custom_packages'] = os.environ['CUSTOM_PACKAGES']

    if os.getenv("TEST_SUITES", None) != "":
        civ_config['test_suites'] = []
        civ_config['test_suites'].extend(os.environ['TEST_SUITES'].strip().split(' '))

    if os.getenv("AWS_EFS", "false").lower() == "true":
        civ_config['tags']['aws-efs'] = True

    print('--- CI selection mode:', run_mode['mode'])
    print('--- SKIP_<CLOUD>:')
    for key, value in vars.items():
        print(key, ':', value)
    if civ_config.get('test_filter'):
        print('--- test_filter:', civ_config['test_filter'])

    config_path = '/tmp/civ_config.yaml'
    vars['CIV_CONFIG_FILE'] = config_path

    write_config_file(config_path, civ_config)
    print('--- civ_config:')
    pprint(civ_config)

    write_vars_file(vars, vars_file_path)
