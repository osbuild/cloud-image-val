import json
import os
from test_suite.suite_runner import SuiteRunner


def main():
    cloudx_components_test_suites = [
        "test_suite/package/test_awscli2.py",
        "test_suite/package/otel_package/test_otel.py",
    ]

    # For this test, we asssume one instance has been deployed at a time.
    with open(os.environ['CIV_INSTANCES_JSON'], 'r') as f:
        inst = json.load(f)

    suite_runner = SuiteRunner(cloud_provider='aws',
                               instances=inst,
                               ssh_config=os.environ['CIV_SSH_CONFIG_FILE'],
                               parallel=False,
                               debug=True)

    status = suite_runner.run_tests(test_suite_paths=cloudx_components_test_suites,
                                    output_filepath=os.environ['CIV_OUTPUT_FILE'])

    return_code = status >> 8

    if return_code == 0:
        return True
    else:
        print("One or more components failed.")
        return False


if __name__ == '__main__':
    main()
