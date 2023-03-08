import os
import subprocess
import sys


def get_files_changed():
    os.system('git remote add upstream https://github.com/osbuild/cloud-image-val.git')
    os.system('git fetch upstream')
    files_changed_cmd = ['git', 'diff', '--name-only', 'HEAD', 'upstream/main']
    files_changed_raw = subprocess.run(files_changed_cmd, stdout=subprocess.PIPE)

    if files_changed_raw.stdout == b'' or files_changed_raw.stderr is not None:
        print('ERROR: git diff command failed or there are no changes in the PR')
        exit()

    return str(files_changed_raw.stdout)[2:-3].split('\\n')


def lines_into_list(file_name):
    list = []
    with open(file_name, 'r') as diff:
        file_started = False

        # Skip the diff header
        for line in diff:
            if not file_started:
                if line[0:2] == '@@':
                    file_started = True
                continue

            list.append(line.rstrip())

    return list


def changed_file_to_diff_list(file_changed):
    # get whole sript diff to list (useful for debugging)
    file_changed_underscore = file_changed.replace('/', '_').replace('.', '_')
    os.system(f'git diff -U10000 --output=/tmp/diff_{file_changed_underscore} HEAD upstream/main {file_changed}')

    # Read file into list
    return lines_into_list(f'/tmp/diff_{file_changed_underscore}')


def find_method_name(direction, line_num, diff):
    if direction == 'above':
        step = -1
        stop = 0
    elif direction == 'below':
        step = 1
        stop = len(diff)
    else:
        print(f'direction has to be "above" or "below", not {direction}')
        exit()

    for i in range(line_num, stop, step):
        raw_line = diff[i][1:].strip()
        if raw_line[0:3] == 'def':
            method = raw_line[4:].split('(')[0]
            return method
        elif raw_line[0:5] == 'class':
            print(f'A class was found before a function, the filter cannot be applied. Class: {raw_line}')
            return None


def get_method_from_changed_line(line_num, diff):
    raw_line = diff[line_num][1:].strip()

    if raw_line[0:3] == 'def':
        print(f'A new method was created, the filter cannot be applied. Method: {raw_line}')
        return None
    elif raw_line[0:1] == '@':
        method = find_method_name('below', line_num, diff)
    else:
        method = find_method_name('above', line_num, diff)

    return method


def get_modified_methods():
    modified_methods = set()
    test_dirs = ['test_suite/cloud/', 'test_suite/generic/']

    files_changed = get_files_changed()
    print('--- Files changed:')
    print(*files_changed, sep='\n')

    for file_changed in files_changed:
        # Check if file is a test suite file
        if test_dirs[0] not in file_changed and test_dirs[1] not in file_changed:
            print(f'{file_changed} is not a test suite file, filter cannot be applied')
            return None

        diff = changed_file_to_diff_list(file_changed)
        for line_num, line in enumerate(diff):
            if line[0:1] in ['+', '-']:
                method = get_method_from_changed_line(line_num, diff)

                if method is None:
                    return None
                elif method[0:4] != 'test':
                    print(f'The method "{method}" is not a test')
                    return None
                else:
                    modified_methods.add(method)

    return modified_methods


def write_vars_file(vars, vars_file_path):
    with open(vars_file_path, 'w+') as vars_file:
        for var in vars:
            if vars[var] is not None:
                vars_file.write(f'export {var}="{vars[var]}"\n')


def get_civ_option_t():
    modified_methods = get_modified_methods()
    if modified_methods is None:
        return None

    print('--- Modified methods:')
    print(*list(modified_methods), sep='\n')
    return '-t ' + ' or '.join(list(modified_methods))


def get_skip_vars():
    skip_vars = {'skip_aws': 'true', 'skip_azure': 'true', 'skip_gcp': 'true'}
    files_changed = get_files_changed()
    for file_changed in files_changed:
        if 'test_suite/generic/' in file_changed:
            skip_vars = {'skip_aws': 'false', 'skip_azure': 'false', 'skip_gcp': 'false'}
            return skip_vars
        elif file_changed == 'test_suite/cloud/test_aws.py':
            skip_vars['skip_aws'] = 'false'
        elif file_changed == 'test_suite/cloud/test_azure.py':
            skip_vars['skip_azure'] = 'false'
        elif file_changed == 'test_suite/cloud/test_gcp.py':
            skip_vars['skip_gcp'] = 'false'

    return skip_vars


if __name__ == '__main__':
    vars_file_path = sys.argv[1]

    # Set CIV_OPTIONS and SKIP_<CLOUD> env variables
    vars = {}

    skip_vars = get_skip_vars()
    option_t = get_civ_option_t()

    # If option_t is different than None, we are applying the filter
    # If it's None, just run CIV with default values, no filter
    if option_t:
        vars['CIV_OPTION_T'] = option_t
        vars['SKIP_AWS'] = skip_vars['skip_aws']
        vars['SKIP_AZURE'] = skip_vars['skip_azure']
        vars['SKIP_GCP'] = skip_vars['skip_gcp']
    else:
        vars['SKIP_AWS'] = 'false'
        vars['SKIP_AZURE'] = 'false'
        vars['SKIP_GCP'] = 'false'

    vars['CIV_OPTION_R'] = '-r=/tmp/resource-file.json'
    vars['CIV_OPTION_D'] = '-d'
    vars['CIV_OPTION_O'] = '-o=/tmp/report.xml'
    vars['CIV_OPTION_M'] = '-m not pub'

    print('--- CIV_OPTIONS and SKIP_<CLOUD>:')
    [print(key, ': ', value) for key, value in vars.items()]

    write_vars_file(vars, vars_file_path)
