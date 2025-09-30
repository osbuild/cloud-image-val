#! /bin/bash -x

################################################################################
#
# rhel-ha-aws-check.sh - Sanity check script for RHEL HA running on AWS.
#
# Author: Brandon Perkins <bperkins@redhat.com>
#
# This script is designed to be run on a single instance and does not perform
# any multi-node tests.  This script validates the ability to install,
# configure, and run the very basics of a pacemaker cluster, the AWS fence
# agent, and the AWS resource agents.
#
################################################################################

# Get the RHEL Major version number as packages and
# PCS commands are different between RHEL7 and RHEL8
RHELMAJOR=$(rpm -q --queryformat="%{VERSION}" \
	      $(rpm -q --whatprovides redhat-release) | cut -d\. -f1)

# List of packages that should be installed when in a
# RHEL HA environment running within AWS EC2:
#           awscli - Universal Command Line Environment for AWS
#       bind-utils - Utilities for querying DNS name servers
# fence-agents-aws - Fence agent for Amazon AWS
#              pcs - Pacemaker Configuration System
#  python-requests - HTTP library, written in Python (RHEL7 only)
HAPKGS="bind-utils fence-agents-aws pcs"
if [ ${RHELMAJOR} -lt 8 ]; then
    #subscription-manager config will be changed without python-requests installed, eg. auto-reg disabled
    echo "python-requests is required by subscription-manager, cloudinit,redhat-cloud-client-configuration, do not remove/install it in RHEL-7"
    #HAPKGS+=" python-requests"
fi
# awscli was dropped from RHEL-9
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/considerations_in_adopting_rhel_9/index#assembly_changes-to-packages_considerations-in-adopting-RHEL-9
if [ ${RHELMAJOR} -lt 9 ]; then
    HAPKGS+=" awscli"
else
    HAPKGS+=" python3-pip resource-agents-cloud"
fi

# For each required package:
#   1) Remove existing package (if it exists)
#   2) Install the package from preconfigured repository
#   3) Check that the package is actually installed
for HAPKG in ${HAPKGS}; do
    rpm -q ${HAPKG}
    if [ $? -eq 0 ]; then
        yum --setopt=clean_requirements_on_remove=True -y remove ${HAPKG}
        if [ $? -ne 0 ]; then
            echo "Removal of ${HAPKG} failed."
            exit 1
        fi
    fi

    yum -y install ${HAPKG}
    if [ $? -ne 0 ]; then
        echo "Install of ${HAPKG} failed."
        exit 1
    else
        rpm -q ${HAPKG}
        if [ $? -ne 0 ]; then
            echo "Install of ${HAPKG} failed."
            exit 1
        fi
    fi
done

# Verify all required packages are installed
rpm -q ${HAPKGS}
if [ $? -ne 0 ]; then
    echo "Not all packages were installed."
    exit 1
fi

# Install awscli from pip
if [ ${RHELMAJOR} -ge 9 ]; then
    python -m venv /tmp/test_env
    source /tmp/test_env/bin/activate
    pip install -U awscli
fi
# Verify that the "pacemaker-libs" package created the "hacluster" user
id hacluster
if [ $? -ne 0 ]; then
    echo "User hacluster does not exist."
    exit 1
fi

# Update the "hacluster" user authentication tokens
echo RedHat1 | passwd --stdin hacluster
if [ $? -ne 0 ]; then
    echo "Password for hacluster could not be changed."
    exit 1
fi

# Stop the PCS remote configuration interface service if it is active
systemctl is-active pcsd.service
if [ $? -eq 0 ]; then
    systemctl stop pcsd.service
    if [ $? -ne 0 ]; then
        echo "Could not stop PCSD service."
        exit 1
    fi
fi

# Disable the PCS remote configuration interface service if it is enabled
systemctl is-enabled pcsd.service
if [ $? -eq 0 ]; then
    systemctl disable pcsd.service
    if [ $? -ne 0 ]; then
        echo "Could not disable PCSD service."
        exit 1
    fi
fi

# Enable and start the PCS remote configuration interface service
systemctl enable --now pcsd.service
if [ $? -ne 0 ]; then
    echo "Could not enable and start PCSD service."
    exit 1
fi

# Verify the PCS remote configuration interface service is enabled
systemctl is-enabled pcsd.service
if [ $? -ne 0 ]; then
    echo "The PCSD service was not enabled."
    exit 1
fi

# Wait for the PCS remote configuration interface service to finish starting
sleep 5

# Verify the PCS remote configuration interface service is active
systemctl is-active pcsd.service
if [ $? -ne 0 ]; then
    echo "The PCSD service was not started."
    exit 1
fi

# In the event that the environment is dirty, presumably from a previous failed
# run of this script (there is intentionally no error detection):
#   1) Make the cluster forget failed operations from history of the resource
#      and re-detect its current state
#   2) Make the cluster forget failed operations from history of the stonith
#      device and re-detect its current state
#   3) Stop the cluster on the local node
#   4) Configure cluster to not run on node boot on the local node
#   5) Permanently destroy the cluster on the local node
pcs resource cleanup
pcs stonith cleanup
pcs cluster stop --request-timeout=20 --force
pcs cluster disable
if [ ${RHELMAJOR} -lt 9 ]; then
    pcs cluster destroy
else
    pcs cluster destroy --force
fi

# Authenticate local pcs/pcsd against pcsd on the local node
if [ ${RHELMAJOR} -lt 8 ]; then
    pcs cluster auth -u hacluster -p RedHat1 localhost
else
    pcs host auth -u hacluster -p RedHat1 localhost
fi
if [ $? -ne 0 ]; then
    echo "Cluster authentication failed."
    exit 1
fi

# Create the cluster on the local node and synchronize the cluster
# configuration files to it
if [ ${RHELMAJOR} -lt 8 ]; then
    pcs cluster setup --force --name newcluster localhost
else
    pcs cluster setup --force newcluster localhost
fi
if [ $? -ne 0 ]; then
    echo "Cluster setup failed."
    exit 1
fi

# Configure cluster to run on the local node at boot
pcs cluster enable
if [ $? -ne 0 ]; then
    echo "Cluster enable failed."
    exit 1
fi

# Start a cluster on the local node
pcs cluster start
if [ $? -ne 0 ]; then
    echo "Cluster start failed."
    exit 1
fi

# Show options for the fence agent for AWS (to verify it is installed)
pcs stonith describe fence_aws
if [ $? -ne 0 ]; then
    echo "Cannot load fence agent fence_aws."
    exit 1
fi

# Create "fence_aws" stonith device with specified type and options
pcs stonith create clusterfence fence_aws
if [ $? -ne 0 ]; then
    echo "Cannot create stonith resource."
    exit 1
fi

# Show the configured options for the "clusterfence" stonith device
if [ ${RHELMAJOR} -lt 8 ]; then
    pcs stonith show clusterfence
else
    pcs stonith config clusterfence
fi
if [ $? -ne 0 ]; then
    echo "Cannot get stonith resource configuration."
    exit 1
fi

# Show status of all currently configured stonith devices
if [ ${RHELMAJOR} -lt 8 ]; then
    pcs stonith
else
    pcs stonith status
fi
if [ $? -ne 0 ]; then
    echo "Cluster stonith status failed."
    exit 1
fi

# Verify that the AWS CLI command runs without errors
aws configure list
if [ $? -ne 0 ]; then
    echo "AWS configuration failed."
    exit 1
fi

# Find all AWS resource agents
RAS=/usr/lib/ocf/resource.d/heartbeat/*aws*

# For each resource agent:
#   1) Show options for the specified resource (to verify it is installed)
#   2) Create specified resource
#   3) Show the configured options for the specified resource ids
for R in ${RAS}; do
    RA=$(basename ${R})

    pcs resource describe ocf:heartbeat:${RA}
    if [ $? -ne 0 ]; then
	echo "Cannot load resource agent ${RA}."
	exit 1
    fi

    # Here the script can exit with a "Warning: required resource options..."
    # The --force flag is intended to bypass this, but it still prints the warning
    # and the resource is created successfully, so the script continues.
    pcs resource create --force ${RA} ocf:heartbeat:${RA}
    if [ $? -ne 0 ]; then
        echo "Cannot create resource agent ${RA} resource."
        exit 1
    fi

    if [ ${RHELMAJOR} -lt 8 ]; then
	pcs resource show ${RA}
    else
	pcs resource config ${RA}
    fi
    if [ $? -ne 0 ]; then
        echo "Cannot get resource configuration for ${RA}."
        exit 1
    fi
done

# Wait for all resources to settle
sleep 20

# Show status of all currently configured resources
if [ ${RHELMAJOR} -lt 8 ]; then
    pcs resource
else
    pcs resource status
fi
if [ $? -ne 0 ]; then
    echo "Cluster resource status failed."
    exit 1
fi

# Check the pacemaker configuration (CIB) for syntax and common conceptual
# errors on the currently running cluster
pcs cluster verify --full
if [ $? -ne 0 ]; then
    echo "Cluster verify failed."
    exit 1
fi

# View all information about the cluster and resources
pcs status --full
if [ $? -ne 0 ]; then
    echo "Cluster status failed."
    exit 1
fi

# For each resource:
#   1) Attempt to stop the resource if it is running and forbid the cluster
#      from starting it again
#   2) Make the cluster forget failed operations from history of the resource
#      and re-detect its current state
#   3) Delete the resource
#   4) Verify the resource is deleted
for R in ${RAS}; do
    RA=$(basename ${R})

    # Disable the resource if it's currently running or failed
    pcs resource disable --wait=5 ${RA}
    # This command can return a non-zero exit code if the resource is already stopped.
    # The script handles this by checking for a return code of 0 or 1.
    if [ $? -ne 0 -a $? -ne 1 ]; then
	echo "Cannot disable resource agent ${RA}."
	exit 1
    fi

    # Clean up any failed operations for the resource
    pcs resource cleanup ${RA}
    if [ $? -ne 0 -a $? -ne 1 ]; then
        echo "Cannot cleanup resource agent ${RA} resource."
        exit 1
    fi

    # Check if the resource exists before attempting to delete it
    # This prevents the script from failing if the resource is already gone.
    pcs resource config ${RA} &> /dev/null
    if [ $? -eq 0 ]; then
        pcs resource delete ${RA}
        if [ $? -ne 0 ]; then
            echo "Cannot delete resource agent ${RA} resource."
            exit 1
        fi
    fi

    if [ ${RHELMAJOR} -lt 8 ]; then
        pcs resource show ${RA}
    else
        pcs resource config ${RA}
    fi
    if [ $? -eq 0 ]; then
        echo "Removal of ${RA} failed."
        exit 1
    fi
done


# Make the cluster forget failed operations from history of the resource
# and re-detect its current state
pcs resource cleanup
if [ $? -ne 0 ]; then
    echo "Unable to cleanup resource configuration."
    exit 1
fi

# Attempt to stop the stonith device if it is running and disallow
# the cluster to use it
pcs stonith disable --wait=5 clusterfence
if [ $? -ne 0 -a $? -ne 1 ]; then
    echo "Cannot disable stonith resource."
    exit 1
fi

# Make the cluster forget failed operations from history of the stonith
# device and re-detect its current state
pcs stonith cleanup clusterfence
if [ $? -ne 0 ]; then
    echo "Cannot cleanup stonith resource."
    exit 1
fi

# Remove stonith id "clusterfence" from configuration
pcs stonith delete clusterfence
if [ $? -ne 0 ]; then
    echo "Cannot delete stonith resource."
    exit 1
fi

# Verify the stonith device is deleted
if [ ${RHELMAJOR} -lt 8 ]; then
    pcs stonith show clusterfence
else
    pcs stonith config clusterfence
fi
if [ $? -eq 0 ]; then
    echo "Got stonith resource configuration."
    exit 1
fi

# Make the cluster forget failed operations from history of the stonith
# device and re-detect its current state
pcs stonith cleanup
if [ $? -ne 0 ]; then
    echo "Unable to cleanup stonith configuration."
    exit 1
fi

# Stop the cluster on the local node
pcs cluster stop --request-timeout=20 --force
if [ $? -ne 0 ]; then
    echo "Cluster stop failed."
    exit 1
fi

# Configure cluster to not run on node boot on the local node
pcs cluster disable
if [ $? -ne 0 ]; then
    echo "Cluster disable failed."
    exit 1
fi

# Permanently destroy the cluster on the local node
if [ ${RHELMAJOR} -lt 9 ]; then
    pcs cluster destroy
else
    pcs cluster destroy --force
fi
if [ $? -ne 0 ]; then
    echo "Cluster destroy failed."
    exit 1
fi

# Stop the PCS remote configuration interface service if it is active
systemctl disable --now pcsd.service
if [ $? -ne 0 ]; then
    echo "Could not disable and stop PCSD service."
    exit 1
fi

# Verify the PCS remote configuration interface service is inactive
systemctl is-active pcsd.service
if [ $? -eq 0 ]; then
    echo "The PCSD service was not stoped."
    exit 1
fi

# Verify the PCS remote configuration interface service is disabled
systemctl is-enabled pcsd.service
if [ $? -eq 0 ]; then
    echo "The PCSD service was not disabled."
    exit 1
fi

# Remove all packages that were installed
yum --setopt=clean_requirements_on_remove=True -y remove ${HAPKGS}
if [ $? -ne 0 ]; then
    echo "Removal of ${HAPKGS} failed."
    exit 1
fi

# Verify that all packages have been removed
for HAPKG in ${HAPKGS}; do
    rpm -q ${HAPKG}
    if [ $? -eq 0 ]; then
        echo "Removal of ${HAPKG} failed."
        exit 1
    fi
done

# Remove awscli
if [ ${RHELMAJOR} -ge 9 ]; then
    pip uninstall -y awscli
    deactivate
    rm -rf /tmp/test_env
fi
# Success
echo "HA check passed successfully."
exit 0
