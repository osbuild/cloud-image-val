import os
import subprocess


def get_files_changed():
    os.system('git remote add upstream https://github.com/osbuild/cloud-image-val.git')
    os.system('git fetch upstream')
    files_changed_cmd = ['git', 'diff', '--name-only', 'HEAD', 'upstream/main']
    files_changed_raw = subprocess.run(files_changed_cmd, stdout=subprocess.PIPE)

    if files_changed_raw.stdout == b'' or files_changed_raw.stderr is not None:
        print('ERROR: git diff command failed or there are no changes in the PR')
        exit()

    return str(files_changed_raw.stdout)[2:-3].split('\\n')


if __name__ == "__main__":
    files_that_update_base = ["requirements.txt", "base.Dockerfile"]
    files_changed = get_files_changed()

    for file_changed in files_changed:
        if files_changed in files_that_update_base:
            print("true")
            exit()

    print("false")
    exit()
