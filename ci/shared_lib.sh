#!/usr/bin/bash

function nvrGreaterOrEqual {
    local rpm_name=$1
    local min_version=$2

    set +e
    rpm_version=$(rpm -q --qf "%{version}" "${rpm_name}")
    rpmdev-vercmp "${rpm_version}" "${min_version}" 1>&2
    local result=$?
    set -e
    
    # 12 - rpm_version < min_version
    if [ "$result" = "12" ]; then
        return 1
    else
        # 11 - rpm_version > min_version
        if [ "$result" = "11" ]; then
            echo "DEBUG: ${rpm_version} >= ${min_version}" 1>&2
            return 0
        # 0 - rpm_version == min_version
        elif [ "$result" = "0" ]; then
            echo "DEBUG: ${rpm_version} == ${min_version}" 1>&2
            return 0
        # Any other result is unexpected
        else
            echo "DEBUG: Unexpected rpmdev-vercmp result: $result" 1>&2
            return 2
        fi
        echo "DEBUG: ${rpm_version} >= ${min_version}" 1>&2
        return 0
    fi
}

function get_build_info() {
    local key="$1"
    local fname="$2"
    if rpm -q --quiet weldr-client; then
        key=".body${key}"
        if nvrGreaterOrEqual "weldr-client" "35.6" 2> /dev/null; then
            key=".[0]${key}"
        fi
    fi
    jq -r "${key}" "${fname}"
}

# Colorful timestamped output.
function greenprint {
    echo -e "\033[1;32m[$(date -Isecond)] ${1}\033[0m"
}

function redprint {
    echo -e "\033[1;31m[$(date -Isecond)] ${1}\033[0m"
}

function error_handler() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        local line_no=${BASH_LINENO[0]}
        local cmd="${BASH_COMMAND}"
        redprint "❌ Pipeline failed with exit code $exit_code"
        redprint "   at line $line_no: $cmd"
    fi
}