#!/bin/bash
git clone https://github.com/osbuild/cloud-cleaner.git
sudo dnf install -yq jq

V2_AZURE_CLIENT_ID=${CLOUDX_AZURE_CLIENT_ID} \
    V2_AZURE_CLIENT_SECRET=${CLOUDX_AZURE_CLIENT_SECRET} \
    AZURE_TENANT_ID=${CLOUDX_AZURE_TENANT_ID} \
    AZURE_RESOURCE_GROUP=${CLOUDX_AZURE_RESOURCE_GROUP} \
    V2_AWS_ACCESS_KEY_ID=${CLOUDX_AWS_ACCESS_KEY_ID} \
    V2_AWS_SECRET_ACCESS_KEY=${CLOUDX_AWS_SECRET_ACCESS_KEY} \
    bash ./cloud-cleaner/cloud_cleaner.sh
