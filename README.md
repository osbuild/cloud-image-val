# cloud-image-val
Multi-cloud image validation tool. Right now it only supports AWS.

# Dependencies
Apart from the python depedencies that can be found in `requirements.txt`, the environment wqhere you will run this tool must have the following packages installed:

- terraform: https://learn.hashicorp.com/tutorials/terraform/install-cli
- aws-cli (if not installed by terraform package): https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# Pre-requisites
- You must have a working AWS account.
- The code is prepared to work wiht the default profile named `aws`.
- The credentials must be stored in ~/.aws/credentials for the `[aws]` profile. See https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_profiles.html for more details.
- Inbound rules must be set to allow SSH connection from (at least) your public IP address in the default Security Group or VPC.

# Usage
Run the main script `cloud-image-val.py` with the corresponding and desired parameters (if applicable):

```
usage: cloud-image-val.py [-h] -r RESOURCES_FILE -o OUTPUT_FILE [-p] [-d]

options:
  -h, --help            show this help message and exit
  -r RESOURCES_FILE, --resources-file RESOURCES_FILE
                        Path to the resources.json file that contains the Cloud provider and the images to use. See cloud/terraform/sample/resources.json to know about the expected file structure.
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file path of the resultant Junit XML test report and others
  -p, --parallel        Use this option to enable parallel test execution mode. Default is DISABLED
  -d, --debug           Use this option to enable debugging mode. Default is DISABLED

```
Example: `python cloud-image-val.py -r cloud/terraform/sample/resources.json -o /tmp/report.xml -p -d`
