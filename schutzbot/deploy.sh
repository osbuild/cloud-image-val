#!/bin/bash
set -euxo pipefail

# The project whose -tests package is installed.
#
# If it is osbuild-composer (the default), it is pulled from the same
# repository as the osbuild-composer under test. For all other projects, the
# "dependants" key in Schutzfile is consulted to determine the repository to
# pull the -test package from.
PROJECT=${1:-osbuild-composer}

# set locale to en_US.UTF-8
sudo dnf install -y glibc-langpack-en
localectl set-locale LANG=en_US.UTF-8

# Colorful output.
function greenprint {
    echo -e "\033[1;32m[$(date -Isecond)] ${1}\033[0m"
}

function retry {
    local count=0
    local retries=5
    until "$@"; do
        exit=$?
        count=$((count + 1))
        if [[ $count -lt $retries ]]; then
            echo "Retrying command..."
            sleep 5
        else
            echo "Command failed after ${retries} retries. Giving up."
            return $exit
        fi
    done
    return 0
}

function setup_repo {
  local project=$1
  local commit=$2
  local priority=${3:-10}

  local REPO_PATH=${project}/${DISTRO_VERSION}/${ARCH}/${commit}
  if [[ "${INTERNAL_NIGHTLY:=false}" == "internal" && "${project}" == "osbuild-composer" ]]; then
    REPO_PATH=nightly/${REPO_PATH}
  fi

  greenprint "Setting up dnf repository for ${project} ${commit}"
  sudo tee "/etc/yum.repos.d/${project}.repo" << EOF
[${project}]
name=${project} ${commit}
baseurl=http://osbuild-composer-repos.s3-website.us-east-2.amazonaws.com/${REPO_PATH}
enabled=1
gpgcheck=0
priority=${priority}
EOF
}

function get_last_passed_commit {
    # Using 'internal' instead of 'true' so it's easier to see the pipelines in the Gitlab page
    if [ "${INTERNAL_NIGHTLY:=false}" == "internal" ]; then
        project_id="34771166"
        base_curl="curl --header PRIVATE-TOKEN:${GITLAB_API_TOKEN}"

        # To get the schedule id use the ../pipeline_schedule endpoint
        if [[ ${VERSION_ID%.*} == "8" ]]; then
            # RHEL 8 scheduled pipeline id
            schedule_id="233735"
        else
            # RHEL 9 scheduled pipeline id
            schedule_id="233736"
        fi

        # Last executed pipeline ID
        pipeline_id=$(${base_curl} "https://gitlab.com/api/v4/projects/${project_id}/pipeline_schedules/${schedule_id}" | jq '.last_pipeline.id')

        warning_date=$(date -d "- 3 days" +%s)
        created_at=$(${base_curl} "https://gitlab.com/api/v4/projects/${project_id}/pipelines/${pipeline_id}" | jq -r '.started_at')
        if [[ $(date -d "${created_at}" +%s) -lt "${warning_date}" ]]; then
            echo "We are using an old scheduled pipeline id, Please update it"
            exit 1
        fi

        statuses=$(${base_curl} "https://gitlab.com/api/v4/projects/${project_id}/pipelines/${pipeline_id}/jobs?per_page=100" | jq -cr '.[] | select(.stage=="rpmbuild") | .status')
        for status in ${statuses}; do 
            if [ "$status" != "success" ]; then 
                echo "Error in last nightly pipeline"
                exit 1
            fi 
        done

        commit=$(${base_curl} "https://gitlab.com/api/v4/projects/${project_id}/pipelines/${pipeline_id}" | jq -r '.sha')
        echo $commit

    else
        commit_list=$(curl -u ${API_USER}:${API_PAT} -s https://api.github.com/repos/osbuild/osbuild-composer/commits?per_page=100  | jq -cr '.[].sha')

        for commit in ${commit_list}; do
            gitlab_status=$(curl -u ${API_USER}:${API_PAT} -s https://api.github.com/repos/osbuild/osbuild-composer/commits/${commit}/status \
                          | jq -cr '.statuses[] | select(.context == "Schutzbot on GitLab") | .state')
            if [[ ${gitlab_status} == "success" ]]; then
                break
            fi
        done
        echo $commit
    fi
}

# Get OS details.
source /etc/os-release
ARCH=$(uname -m)
DISTRO_CODE="${DISTRO_CODE:-${ID}-${VERSION_ID//./}}"

if [[ $ID == "rhel" && ${VERSION_ID%.*} == "9" ]]; then
  # There's a bug in RHEL 9 that causes /tmp to be mounted on tmpfs.
  # Explicitly stop and mask the mount unit to prevent this.
  # Otherwise, the tests will randomly fail because we use /tmp quite a lot.
  # See https://bugzilla.redhat.com/show_bug.cgi?id=1959826
  greenprint "Disabling /tmp as tmpfs on RHEL 9"
  sudo systemctl stop tmp.mount && sudo systemctl mask tmp.mount
fi

if [[ $ID == "centos" && $VERSION_ID == "8" ]]; then
    # Workaround for https://bugzilla.redhat.com/show_bug.cgi?id=2065292
    # Remove when podman-4.0.2-2.el8 is in Centos 8 repositories
    greenprint "Updating libseccomp on Centos 8"
    sudo dnf upgrade -y libseccomp
fi

# Distro version that this script is running on.
DISTRO_VERSION=${ID}-${VERSION_ID}

if [[ "$ID" == rhel ]] && sudo subscription-manager status; then
  # If this script runs on subscribed RHEL, install content built using CDN
  # repositories.
  DISTRO_VERSION=rhel-${VERSION_ID%.*}-cdn

  # workaround for https://github.com/osbuild/osbuild/issues/717
  sudo subscription-manager config --rhsm.manage_repos=1
fi

greenprint "Enabling fastestmirror to speed up dnf 🏎️"
echo -e "fastestmirror=1" | sudo tee -a /etc/dnf/dnf.conf

# TODO: include this in the jenkins runner (and split test/target machines out)
sudo dnf -y install jq

# Get latest commit from osbuild-composer main branch
GIT_COMMIT=$(get_last_passed_commit)

setup_repo osbuild-composer "${GIT_COMMIT}" 5

OSBUILD_GIT_COMMIT=$(cat Schutzfile | jq -r '.["'"${ID}-${VERSION_ID}"'"].dependencies.osbuild.commit')
if [[ "${OSBUILD_GIT_COMMIT}" != "null" ]]; then
  setup_repo osbuild "${OSBUILD_GIT_COMMIT}" 10
fi

if [[ "$PROJECT" != "osbuild-composer" ]]; then
  PROJECT_COMMIT=$(jq -r ".[\"${ID}-${VERSION_ID}\"].dependants[\"${PROJECT}\"].commit" Schutzfile)
  setup_repo "${PROJECT}" "${PROJECT_COMMIT}" 10

  # Get a list of packages needed to be preinstalled before "${PROJECT}-tests".
  # Useful mainly for EPEL.
  PRE_INSTALL_PACKAGES=$(jq -r ".[\"${ID}-${VERSION_ID}\"].dependants[\"${PROJECT}\"].pre_install_packages[]?" Schutzfile)

  if [ "${PRE_INSTALL_PACKAGES}" ]; then
    # shellcheck disable=SC2086 # We need to pass multiple arguments here.
    sudo dnf -y install ${PRE_INSTALL_PACKAGES}
  fi
fi

if [ -f "rhel${VERSION_ID%.*}internal.repo" ]; then
    greenprint "Preparing repos for internal build testing"
    sudo mv rhel"${VERSION_ID%.*}"internal.repo /etc/yum.repos.d/
fi

greenprint "Installing test packages for ${PROJECT}"

# NOTE: WORKAROUND FOR DEPENDENCY BUG
retry sudo dnf -y upgrade selinux-policy

# Note: installing only -tests to catch missing dependencies
retry sudo dnf -y install "${PROJECT}-tests" 

# Save osbuild-composer NVR to a file to be used as CI artifact
rpm -q osbuild-composer > COMPOSER_NVR

if [ "${INTERNAL_NIGHTLY:=false}" == "internal" ]; then
    # check if we've installed the osbuild-composer RPM from the nightly tree
    # under test or happen to install a newer version from one of the S3 repositories
    rpm -qi osbuild-composer
    if ! rpm -qi osbuild-composer | grep "Build Host" | grep "redhat.com"; then
        echo "ERROR: Installed osbuild-composer RPM is not the official one"
        exit 2
    else
        echo "INFO: Installed osbuild-composer RPM seems to be official"
    fi

    # cross-check the installed RPM against the one under COMPOSE_URL
    source schutzbot/define-compose-url.sh

    INSTALLED=$(rpm -q --qf "%{name}-%{version}-%{release}.%{arch}.rpm" osbuild-composer)
    RPM_URL="${COMPOSE_URL}/compose/AppStream/${ARCH}/os/Packages/${INSTALLED}"
    RETURN_CODE=$(curl --silent -o -I -L -s -w "%{http_code}" "${RPM_URL}")
    if [ "$RETURN_CODE" != 200 ]; then
        echo "ERROR: Installed ${INSTALLED} not found at ${RPM_URL}. Response was ${RETURN_CODE}"
        exit 3
    else
        echo "INFO: Installed ${INSTALLED} found at ${RPM_URL}, which matches SUT!"
    fi
fi

if [ -n "${CI}" ]; then
    # copy repo files b/c GitLab can't upload artifacts
    # which are outside the build directory
    cp /etc/yum.repos.d/*.repo "$(pwd)"
fi
