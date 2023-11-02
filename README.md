# The cloud-image-val project (CIV)
Multi-cloud image validation tool, also known as "CIV". Right now it supports AWS, Azure and GCP.

The purpose of developing CIV is to have a single tool to test cloud images of Unix systems, no matter the cloud, no matter the distribution.

Although the tool focuses on Red Hat Enterprise Linux cloud images and similar, the tool can be expanded easily to other distributions/systems. 

# Dependencies to use CIV in local environments
Apart from the python dependencies that can be found in `requirements.txt`, the environment where you will run this tool locally must have the following packages installed:

_The dependencies below don't apply if you will use the containerized version of the tool_ --> (highly recommended - see section below about the usage)

- Terraform: https://learn.hashicorp.com/tutorials/terraform/install-cli
- AWS cli: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
- Azure cli (AKA "az"): https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=dnf
- GCloud cli ("gcloud"): https://cloud.google.com/sdk/docs/install

# Prerequisites before running CIV
Below you will find the specific requirements to make CIV work depending on the cloud provider.
Some steps below will be automated in later versions of the tool.

### AWS
- You must have a working AWS account.
- The code is prepared to work with authentication via the use of credentials file (easier) or environment variables:
  - If you use the credentials file, you have to export your profile with the variable `AWS_PROFILE`
  - https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
  - https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
- **Inbound rules** must be set to **allow SSH** connection from (at least) your public IP address in the default Security Group or VPC.
- All regions that are going to be used have to be enabled in your aws account

### Azure
- You must have a working Azure account.
- Be the **admin** of a **Resource Group** where all test VMs (and all dependent resources) will be deployed.
- Login to your Azure account by using **az cli** before using CIV:
  - https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli
- You must set up a **service principal** as per the following guide:
  - https://learn.hashicorp.com/tutorials/terraform/azure-build?in=terraform/azure-get-started#create-a-service-principal
- And **export** the corresponding environment variables as per the guide:
  - https://learn.hashicorp.com/tutorials/terraform/azure-build?in=terraform/azure-get-started#set-your-environment-variables

### Google Cloud (GCP)
Today, the code is not prepared to be run in automation, and it only works locally.
- You must have a working GCP account.
- You must previously login to your GCP account by using gcloud cli tool:
  - `gcloud auth application-default login`

# Usage
Run the main script `cloud-image-val.py` with the corresponding and desired parameters (if applicable):

```
usage: cloud-image-val.py [-h] -r RESOURCES_FILE -o OUTPUT_FILE [-t TEST_FILTER] [-m INCLUDE_MARKERS] [-p] [-d]
                          [-s]

options:
  -h, --help            show this help message and exit
  -r RESOURCES_FILE, --resources-file RESOURCES_FILE
                        Path to the resources JSON file that contains the Cloud provider and the images to use.
                        See cloud/sample/resources_<cloud>.json to know about the expected file structure.
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file path of the resultant Junit XML test report and others
  -t TEST_FILTER, --test-filter TEST_FILTER
                        Use this option to filter tests execution by test name
  -m INCLUDE_MARKERS, --include-markers INCLUDE_MARKERS
                        Use this option to specify which tests to run that match a pytest markers expression.
                        The only marker currently supported is "pub" (see pytest.ini for more details)
                        Example:
                        	-m "pub" --> run tests marked as "pub", which is for images are already published
                        	-m "not pub" --> exclude "pub" tests
                        More information about pytest markers:
                        --> https://doc.pytest.org/en/latest/example/markers.html
  -p, --parallel        Use this option to enable parallel test execution mode. Default is DISABLED
  -d, --debug           Use this option to enable debugging mode. Default is DISABLED
  -s, --stop-cleanup    Use this option to enable stop cleanup process until a key is pressed. 
                        Helpful when you need to connect through ssh to an instance. Default is DISABLED
  -e ENVIRONMENT, --environment ENVIRONMENT
                        Use this option to set what invironment CIV is going to run on.
                        This can change CIV bahaviour like how "-s" works. this option can be
                        set to "automated" or "local". Default is "local"
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Use this option to pass CLI options through a config file.
                        This config should be in yaml format, examples can be found at the end of this README
  --tags TAGS           Use this option to add tags to created cloud resources and modify CIV behaviour.
                        This tags should be passed in json format as in this example:
                        --tags '{"key1": "value1", "key2": "value2"}'
  -rp, --report-portal  Use this option to upload the JUnit XML test results to your Report Portal project.
                        Make sure to set the correct environment variables as explained in the README doc.
```

Example of running CIV locally:
```
# then, run CIV 
python cloud-image-val.py -r cloud/terraform/sample/resources_aws.json -o /tmp/report.xml -p -d
```

## Using CIV's container from quay.io (recommended)
You can simply use the latest container version of the tool, which already has all the dependencies and tools preinstalled (such as Terraform).

Example (using podman, but it should work the same way with docker):
```
podman pull quay.io/cloudexperience/cloud-image-val:latest
```

Then you can connect to the container in interactive mode and run CIV as if you were running it in local:
```
podman run -it quay.io/cloudexperience/cloud-image-val:latest
```

Or, you can pass the environment variables and even map a local directory so that the resultant HTML report is stored there.
Example of running CIV without interactive mode, passing all the credentials and mapping a local path to save the report (recommended):
```
podman run \
  -a stdout -a stderr \
  -e AWS_ACCESS_KEY_ID="<your_aws_key_id>" \
  -e AWS_SECRET_ACCESS_KEY="<your_aws_secret_key>" \
  -e AWS_REGION="<your_aws_default_region>" \
  -v <some_local_dir_path>:/tmp:Z \
  quay.io/cloudexperience/cloud-image-val:latest \
  python cloud-image-val.py -r cloud/sample/resources_aws_marketplace.json -p -o /tmp/report.xml
```

As an alternative, you could also use your credentials stored in ~/.aws/credentials by exporting the variable AWS_PROFILE and binding the ~/.aws/ folder to the container:
```
podman run \
  -a stdout -a stderr \
  -e AWS_PROFILE="<your_aws_profile>" \
  -v <some_local_dir_path>:/tmp:Z \
  -v $HOME/.aws/:/opt/app-root/src/.aws/:Z \
  quay.io/cloudexperience/cloud-image-val:latest \
  python cloud-image-val.py -r cloud/sample/resources_aws_marketplace.json -p -o /tmp/report.xml
```

**NOTE**: The example above uses AWS, but the same can be done for Azure too. The only cloud not working with environment variables right now is GCP.

# Contribution guide
Below you will find different sections that cover the aspects of contributing to this project, from the code base until the test suites used to test Linux cloud images.

## Following clean code best practices
  - Think carefully about naming and formatting. We use PEP-8 and flake8 for code linting.
  - Follow the scouts rule: Leave the place cleaner than you found it.
  - Unit tests and code coverage, whenever makes sense.
  - Try to get at least one reviewer's code review and approval before merging.
  - Work on your fork, not on the upstream.
    - Create pull requests to merge code from your fork branches >> to upstream main.
  - Take care of Automation/CI and pay attention to warnings and errors raised there.

## Creating and maintaining test suites
In this section we will cover the basic aspects of creating new test suites and adding test cases into them.

It is important to mention that the core of the testing is made with the combination of pytest + different plugins/libraries that add a bunch of testing features.

Some of the most relevant libraries and plugins used in this project are:
- [pytest-testinfra](https://testinfra.readthedocs.io/en/latest/index.html): The core of the core. This framework allows us to interact with the running instances in real time and do almost anything we need in our tests. Examples are:
  - Running commands, getting their output, etc.
  - Checking file properties, content and directories, permissions, etc.
  - Checking services and packages, their statues, if they are installed, etc.
  - And much, much more!
- [pytest-xdist](https://pytest-xdist.readthedocs.io/en/latest/): Allows us to run tests in parallel in all the deployed instances, and balancing the load between all of them
- [pytest-html](https://pytest-html.readthedocs.io/en/latest/): A library for converting Junit XML test results into a nice stand-alone HTML file. It is highly customizable, such as we did in conftest.py

### About pytest markers
There are markers that are mandatory, and they are defined in the pytest.ini file and checked in the conftest.py file (`check_markers()` function).

The main markers are the following ones:
- `run_on`: It allows to specify host distro, version or added operators ('<', '<=', '>' or '>=') where the test case is applicable to. It accepts a python list as argument. `run_on` needs to be specified for each test case, it's a mandatory marker. If you want to make the test run everywhere, just use `@pytest.mark.run_on(['all'])`.
- `exclude_on`: It skips the test according to the specified host distro, version or added operators ('<', '<=', '>' or '>='). It accepts a python list as argument.

  Examples:
  ```
  @pytest.mark.run_on(['all'])
  @pytest.mark.exclude_on(['<=rhel8.5', 'centos9','fedora'])
  ```
  All instances lower or equal than rhel8.5 will be skipped (this includes other major versions, rhel 7, 6...), centos9 will be skipped and instances that are fedora distribution will be also skipped. 
  ```
  @pytest.mark.run_on(['>=rhel9.0', 'fedora'])
  @pytest.mark.exclude_on(['rhel9.0'])
  ```
  This will run the test an all fedora instances and on rhel instances bigger or equal than 9.1. If "run_on" & "exclude_on" markers are both specified, the exclude_on marker always overrules.
- `jira_skip`: It allows you to skip a test if one or more JIRA tickets are NOT closed. Example: `@pytest.mark.jira_skip(['CLOUDX-190', 'CLOUDX-42'])`
- `pub`: It allows us to filter for test cases applicable to "published" images. That means, anything that is marked as "pub" is considered to be only run on production-ready images (e.g. final testing before they are published, or right after they are published).

There are other markers that are intended to add extra information and context to the test cases while being run.

Examples of these special markers are:
- `instance_data`
- `instance_data_aws_cli` (and `_web`)
- `instance_data_azure_web`

The markers above obtain instance data from different sources, and they should be added on-demand if they need to be used.
Example:
```
def test_my_instance_is_not_aws(self, host, instance_data):
    current_cloud_provider = instance_data['cloud']
    if current_cloud_provider == 'aws':
        pytest.skip('This test case does not apply to AWS images.')
    ...
```

The `instance_data` marker is primarily used to get the cloud provider of the resultant instance. This way, certain tests can be skipped if they don't apply to certain cloud provider(s). 

The `host` marker is from **testinfra** and should **always** be there. This way the test can interact with the running instance via SSH and provide results for that specific instance.

### Following the Pytest approach
We use files that contain classes and then those classes contain functions that are the actual test cases.

This way, the test cases can be categorized, markers can be applied to certain groups of tests, etc.

**Important guidelines:**
- Make sure to check if the test applies to all cloud providers (`generic`) or if only applies to certain clouds.
  - That's why we have different directories that are for specific clouds (`test_suite/cloud`)
  - If the test applies to some clouds and does not apply to others, then it's better to add it under the generic directory, and then inside the test, skip whenever appropriate.

### Config file
You can also provide th CLI parameters through a config file in yaml format. This file is always created, even if you provide the parameters through the CLI, the default file is /tmp/civ_config.yml. Here is an example of a config file:
```
config_file: /tmp/civ_config.yml
debug: true
environment: local
output_file: /tmp/civ.xml
resources_file: cloud/sample/resources_aws_marketplace.json
tags:
  key1: value1
  key2: value2
```