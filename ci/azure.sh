#!/bin/bash

#
# Test osbuild-composer 'upload to azure' functionality. To do so, create and
# push a blueprint with composer cli. Then, create an instance in Azure
# from the uploaded VHD image. Finally, run cloud-image-val to verify the
# instance.
#

set -euo pipefail

source ci/set-env-variables.sh
source ci/shared_lib.sh

# Container image used for cloud provider CLI tools
CONTAINER_IMAGE_CLOUD_TOOLS="quay.io/osbuild/cloud-tools:latest"

# Provision the software under test.
ci/provision.sh none

# Check available container runtime
if which podman 2>/dev/null >&2; then
    CONTAINER_RUNTIME=podman
elif which docker 2>/dev/null >&2; then
    CONTAINER_RUNTIME=docker
else
    echo No container runtime found, install podman or docker.
    exit 2
fi

TEMPDIR=$(mktemp -d)
function cleanup() {
    greenprint "== Script execution stopped or finished - Cleaning up =="
    sudo rm -rf "$TEMPDIR"
}
trap cleanup EXIT

CI="${CI:-false}"
if [[ "$CI" == true ]]; then
  TEST_ID="$DISTRO_CODE-$ARCH-$CI_COMMIT_BRANCH-$CI_JOB_ID"
else
  TEST_ID=$(uuidgen);
fi

ARTIFACTS="${ARTIFACTS:-/tmp/artifacts}"

# Set up temporary files.
AZURE_CONFIG=${TEMPDIR}/azure.toml
BLUEPRINT_FILE=${TEMPDIR}/blueprint.toml
COMPOSE_START=${TEMPDIR}/compose-start-${TEST_ID}.json
COMPOSE_INFO=${TEMPDIR}/compose-info-${TEST_ID}.json

# Azure CLI setup
if ! hash az; then
    echo "Using 'azure-cli' from a container"
    sudo "${CONTAINER_RUNTIME}" pull ${CONTAINER_IMAGE_CLOUD_TOOLS}

    AZURE_CMD_CREDS_DIR="${TEMPDIR}/azure-cli_credentials"
    mkdir "${AZURE_CMD_CREDS_DIR}"

    AZURE_CMD="sudo ${CONTAINER_RUNTIME} run --rm \
        --net=host \
        -v ${AZURE_CMD_CREDS_DIR}:/root/.azure:Z \
        -v ${TEMPDIR}:${TEMPDIR}:Z \
        ${CONTAINER_IMAGE_CLOUD_TOOLS} az"
else
    echo "Using pre-installed 'azure-cli' from the system"
    AZURE_CMD="az"
fi
$AZURE_CMD version

# Get the compose log.
get_compose_log () {
    COMPOSE_ID=$1
    LOG_FILE=${ARTIFACTS}/osbuild-${ID}-${VERSION_ID}-azure.log

    # Download the logs.
    sudo composer-cli compose log "$COMPOSE_ID" | tee "$LOG_FILE" > /dev/null
}

# Get the compose metadata.
get_compose_metadata () {
    COMPOSE_ID=$1
    METADATA_FILE=${ARTIFACTS}/osbuild-${ID}-${VERSION_ID}-azure.json

    # Download the metadata.
    sudo composer-cli compose metadata "$COMPOSE_ID" > /dev/null

    # Find the tarball and extract it.
    TARBALL=$(basename "$(find . -maxdepth 1 -type f -name "*-metadata.tar")")
    sudo tar -xf "$TARBALL"
    sudo rm -f "$TARBALL"

    # Move the JSON file into place.
    sudo cat "${COMPOSE_ID}".json | jq -M '.' | tee "$METADATA_FILE" > /dev/null
}

# Write an Azure TOML file
set +x
tee "$AZURE_CONFIG" > /dev/null << EOF
provider = "azure"

[settings]
storageAccount = "${AZURE_STORAGE_ACCOUNT}"
storageAccessKey = "${AZURE_STORAGE_ACCESS_KEY}"
container = "${AZURE_CONTAINER_NAME}"
EOF
set -x

# Write a basic blueprint for our image.
tee "$BLUEPRINT_FILE" > /dev/null << EOF
name = "bash"
description = "A base system"
version = "0.0.1"
EOF

# Append any packages that we want to install
if ! [ -z "$CLOUDX_PKG_TESTING" ]; then
    if ! [ -z "$CUSTOM_PACKAGES" ]; then
        # shellcheck disable=SC2068
        for pkg in ${CUSTOM_PACKAGES[@]}; do
            pkg_name="${pkg%:*}"
            pkg_version="${pkg##*:}"

            if [[ "$pkg_version" == "$pkg_name" ]]; then
                pkg_version='*'
            fi

            echo "[[packages]]
    name = \"$pkg_name\"
    version = \"$pkg_version\"

    " >> "$BLUEPRINT_FILE"
        done
    fi
fi

# Prepare the blueprint for the compose.
greenprint "📋 Preparing blueprint"
sudo composer-cli blueprints push "$BLUEPRINT_FILE"
sudo composer-cli blueprints depsolve bash

# Get worker unit file so we can watch the journal.
WORKER_UNIT=$(sudo systemctl list-units | grep -o -E "osbuild.*worker.*\.service")
sudo journalctl -af -n 1 -u "${WORKER_UNIT}" &
WORKER_JOURNAL_PID=$!
# Stop watching the worker journal when exiting.
trap 'sudo pkill -P ${WORKER_JOURNAL_PID}' EXIT

# Start the compose and upload to Azure.
greenprint "🚀 Starting compose"
sudo composer-cli --json compose start bash vhd "$TEST_ID" "$AZURE_CONFIG" | tee "$COMPOSE_START"
COMPOSE_ID=$(get_build_info ".build_id" "$COMPOSE_START")

# Wait for the compose to finish.
greenprint "⏱ Waiting for compose to finish: ${COMPOSE_ID}"
while true; do
    sudo composer-cli --json compose info "${COMPOSE_ID}" | tee "$COMPOSE_INFO" > /dev/null
    COMPOSE_STATUS=$(get_build_info ".queue_status" "$COMPOSE_INFO")

    # Is the compose finished?
    if [[ $COMPOSE_STATUS != RUNNING ]] && [[ $COMPOSE_STATUS != WAITING ]]; then
        break
    fi

    # Wait 30 seconds and try again.
    sleep 30
done

# Capture the compose logs from osbuild.
greenprint "💬 Getting compose log and metadata"
get_compose_log "$COMPOSE_ID"
get_compose_metadata "$COMPOSE_ID"

# Kill the journal monitor immediately and remove the trap
sudo pkill -P ${WORKER_JOURNAL_PID}
trap - EXIT

# Did the compose finish with success?
if [[ $COMPOSE_STATUS != FINISHED ]]; then
    redprint "Something went wrong with the compose. 😢"
    exit 1
fi

BLOB_URL="https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/${AZURE_CONTAINER_NAME}/${TEST_ID}.vhd"
greenprint "🔍 VHD uploaded to: ${BLOB_URL}"

if [[ "$ID" == "fedora" ]]; then
  SSH_USER="fedora"
else
  SSH_USER="azure"
fi

greenprint "Pulling cloud-image-val container"

if [[ "$CI_PROJECT_NAME" =~ "cloud-image-val" ]]; then
  # If running on CIV, get dev container
  TAG=${CI_COMMIT_REF_SLUG}
else
  # If not, get prod container
  TAG="prod"
fi

CONTAINER_CLOUD_IMAGE_VAL="quay.io/cloudexperience/cloud-image-val:$TAG"

sudo "${CONTAINER_RUNTIME}" pull "${CONTAINER_CLOUD_IMAGE_VAL}"

greenprint "Running cloud-image-val on generated image"

tee "${TEMPDIR}/resource-file.json" <<EOF
{
    "subscription_id": "${CLOUDX_AZURE_SUBSCRIPTION_ID}",
    "resource_group": "${CLOUDX_AZURE_RESOURCE_GROUP}",
    "provider": "azure",
    "instances": [
        {
            "vhd_uri": "${BLOB_URL}",
            "arch": "$ARCH",
            "storage_account": "${AZURE_STORAGE_ACCOUNT}",
            "location": "eastus",
            "username": "$SSH_USER",
            "name": "civ-pkg-testing-image"
        }
    ]
}
EOF

if [ -z "$CIV_CONFIG_FILE" ]; then
    redprint "ERROR: please provide the variable CIV_CONFIG_FILE"
    exit 1
fi

cp "${CIV_CONFIG_FILE}" "${TEMPDIR}/civ_config.yml"

set +x
sudo "${CONTAINER_RUNTIME}" run \
    -a stdout -a stderr \
    -e ARM_CLIENT_ID="${CLOUDX_AZURE_CLIENT_ID}" \
    -e ARM_CLIENT_SECRET="${CLOUDX_AZURE_CLIENT_SECRET}" \
    -e ARM_TENANT_ID="${CLOUDX_AZURE_TENANT_ID}" \
    -e ARM_SUBSCRIPTION_ID="${CLOUDX_AZURE_SUBSCRIPTION_ID}" \
    -v "${TEMPDIR}":/tmp:Z \
    "${CONTAINER_CLOUD_IMAGE_VAL}" \
    python cloud-image-val.py \
    -c /tmp/civ_config.yml
set -x

CIV_EXIT_CODE=$?

mv "${TEMPDIR}"/report.html "${ARTIFACTS}"

# Clean up Azure resources.
KEEP_GENERATED_AMI="${KEEP_GENERATED_AMI:-}"
if [[ -z $KEEP_GENERATED_AMI || $KEEP_GENERATED_AMI == "false" ]]; then
    greenprint "🧼 Cleaning up"
    $AZURE_CMD storage blob delete \
        --account-name "${AZURE_STORAGE_ACCOUNT}" \
        --account-key "${AZURE_STORAGE_ACCESS_KEY}" \
        --container-name "${AZURE_CONTAINER_NAME}" \
        --name "${TEST_ID}.vhd" || true
fi

# Also delete the compose so we don't run out of disk space
sudo composer-cli compose delete "${COMPOSE_ID}" > /dev/null

# Use the return code of the smoke test to determine if we passed or failed.
case $CIV_EXIT_CODE in
    0)
        greenprint "💚 Success"
        exit 0
        ;;
    5)
        echo "❗ No tests were run"
        exit 0
        ;;
    100)
        redprint "❌ Failed (cloud deployment/destroy issues)"
        exit 1
        ;;
    *)
        redprint "❌ Failed (exit code: ${CIV_EXIT_CODE})"
        exit 1
        ;;
esac

exit 0
