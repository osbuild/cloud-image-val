"""
This script exports checks which files and test methods have changed. If the only thing
that changed in the PR are test methods, only execute those.

To do so, it creates bash script with "SKIP_<CLOUD>" variables and "CIV_CONFIG_FILE" that
is a file with the configuration of CIV in yaml format.
"""

import os
import subprocess
import sys
import yaml

from pprint import pprint


DEFAULT_CIV_CONFIG_PATH = "/tmp/civ_config.yaml"

CIV_CONFIG = {
    "resources_file": "/tmp/resource-file.json",
    "output_file": "/tmp/report.xml",
    "environment": "automated",
    "tags": {
        "Workload": "CI Runner",
        "Job_name": "In_CI_Cloud_Test:" + os.getenv("CI_JOB_NAME", ""),
        "Project": "CIV",
        "Branch": os.getenv("CI_COMMIT_REF_SLUG", ""),
        "Pipeline_id": os.getenv("CI_PIPELINE_ID", ""),
        "Pipeline_source": os.getenv("CI_PIPELINE_SOURCE", ""),
    },
    "debug": True,
    "include_markers": "not pub",
    "test_filter": None,
}

ENV_VARS_TO_EXPORT = {}

# Initialize SKIP_<cloud> env vars
ENV_VARS_TO_EXPORT["SKIP_AWS"] = "false"
ENV_VARS_TO_EXPORT["SKIP_AZURE"] = "false"
ENV_VARS_TO_EXPORT["SKIP_GCP"] = "false"


def get_files_changed():
    os.system("git remote add upstream https://github.com/osbuild/cloud-image-val.git")
    os.system("git fetch upstream")
    files_changed_cmd = ["git", "diff", "--name-only", "HEAD", "upstream/main"]
    files_changed_raw = subprocess.run(files_changed_cmd, stdout=subprocess.PIPE)

    if files_changed_raw.stdout == b"" or files_changed_raw.stderr is not None:
        print("ERROR: git diff command failed or there are no changes in the PR")
        exit()

    return str(files_changed_raw.stdout)[2:-3].split("\\n")


def lines_into_list(file_name):
    list = []
    with open(file_name, "r") as diff:
        file_started = False

        # Skip the diff header
        for line in diff:
            if not file_started:
                if line[0:2] == "@@":
                    file_started = True
                continue

            list.append(line.rstrip())

    return list


def changed_file_to_diff_list(file_changed):
    # get whole sript diff to list (useful for debugging)
    file_changed_underscore = file_changed.replace("/", "_").replace(".", "_")
    os.system(
        f"git diff -U10000 --output=/tmp/diff_{file_changed_underscore} HEAD upstream/main {file_changed}"
    )

    # Read file into list
    return lines_into_list(f"/tmp/diff_{file_changed_underscore}")


def find_method_name(direction, line_num, diff):
    if direction == "above":
        step = -1
        stop = 0
    elif direction == "below":
        step = 1
        stop = len(diff)
    else:
        print(f'direction has to be "above" or "below", not {direction}')
        exit()

    for i in range(line_num, stop, step):
        raw_line = diff[i][1:].strip()
        if raw_line[0:3] == "def":
            method = raw_line[4:].split("(")[0]
            return method
        elif raw_line[0:5] == "class":
            print(
                f"A class was found before a function, the filter cannot be applied. Class: {raw_line}"
            )
            return None


def get_method_from_changed_line(line_num, diff):
    raw_line = diff[line_num][1:].strip()

    if raw_line[0:3] == "def":
        method = find_method_name("above", line_num + 1, diff)
    elif raw_line[0:1] == "@":
        method = find_method_name("below", line_num, diff)
    else:
        method = find_method_name("above", line_num, diff)

    return method


def get_modified_methods():
    modified_methods = set()
    test_dirs = ["test_suite/cloud/", "test_suite/generic/"]

    files_changed = get_files_changed()
    print("--- Files changed:")
    print(*files_changed, sep="\n")

    for file_changed in files_changed:
        # Check if file is a test suite file
        if test_dirs[0] not in file_changed and test_dirs[1] not in file_changed:
            print(f"{file_changed} is not a test suite file, filter cannot be applied")
            return None

        diff = changed_file_to_diff_list(file_changed)
        for line_num, line in enumerate(diff):
            if line[0:1] in ["+", "-"]:
                method = get_method_from_changed_line(line_num, diff)

                if method is None:
                    return None
                elif method[0:4] != "test":
                    print(f'The method "{method}" is not a test')
                    return None
                else:
                    modified_methods.add(method)

    return modified_methods


def write_vars_file(vars, vars_file_path):
    with open(vars_file_path, "w+") as vars_file:
        for var in vars:
            if ENV_VARS_TO_EXPORT[var] is not None:
                vars_file.write(f'export {var}="{vars[var]}"\n')


def get_modified_methods_str():
    modified_methods = get_modified_methods()
    if modified_methods is None:
        return None

    print("--- Modified methods:")
    print(*list(modified_methods), sep="\n")
    return " or ".join(list(modified_methods))


def get_skip_vars():
    skip_vars = {
        "skip_aws": "false",
        "skip_azure": "false",
        "skip_gcp": "false"
    }

    files_changed = get_files_changed()

    for file in files_changed:
        if "test_suite/generic/.*" in file:
            return skip_vars

    return {
        "skip_aws": "test_suite/cloud/test_aws.py" in files_changed,
        "skip_azure": "test_suite/cloud/test_azure.py" in files_changed,
        "skip_gcp": "test_suite/cloud/test_gcp.py" in files_changed,
    }


def write_config_file(config_path, civ_config):
    with open(config_path, "w+") as config_file:
        yaml.dump(civ_config, config_file)


if __name__ == "__main__":
    vars_file_path = sys.argv[1]

    modified_methods_str = None
    if os.getenv("CI_COMMIT_REF_SLUG", "") != "main":
        skip_vars = get_skip_vars()
        modified_methods_str = get_modified_methods_str()

    # The env vars of this block come from ci/.gitlab-ci-cloud-experience.yaml
    if os.getenv("CLOUDX_PKG_TESTING", "false") == "true":
        if "CUSTOM_PACKAGES" in os.environ:
            CIV_CONFIG["tags"]["custom_packages"] = os.getenv("CUSTOM_PACKAGES", "")

        # This env var comes from GitLab CI pipeline
        if "TEST_SUITES" in os.environ:
            CIV_CONFIG["test_suites"] = []
            CIV_CONFIG["test_suites"].extend(os.getenv("TEST_SUITES", "").split(" "))

        # This env var comes from GitLab CI pipeline
        if os.getenv("AWS_EFS", "false").lower() == "true":
            CIV_CONFIG["tags"]["aws-efs"] = True

    # If modified_methods_str is not None, we might need to skip some clouds.
    # If it's None, just run CIV in all clouds, no skipping.
    if modified_methods_str:
        ENV_VARS_TO_EXPORT["SKIP_AWS"] = skip_vars["skip_aws"]
        ENV_VARS_TO_EXPORT["SKIP_AZURE"] = skip_vars["skip_azure"]
        ENV_VARS_TO_EXPORT["SKIP_GCP"] = skip_vars["skip_gcp"]

    print("--- SKIP_<CLOUD> vars:")
    pprint(skip_vars)

    ENV_VARS_TO_EXPORT["CIV_CONFIG_FILE"] = DEFAULT_CIV_CONFIG_PATH

    write_config_file(DEFAULT_CIV_CONFIG_PATH, CIV_CONFIG)
    print("--- civ_config:")
    pprint(CIV_CONFIG)

    write_vars_file(ENV_VARS_TO_EXPORT, vars_file_path)
