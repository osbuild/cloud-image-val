import os
import json

INSTANCES_JSON_PATH = os.environ['CIV_INSTANCES_JSON']


def __get_instance_data_from_json(key_to_find, values_to_find, path=INSTANCES_JSON_PATH):
    with open(path, 'r') as f:
        instances_json_data = json.load(f)
    for instance in instances_json_data.values():
        if key_to_find in instance.keys() and instance[key_to_find] in values_to_find:
            return instance


def check_avc_denials(host, relevant_keywords=None):
    """
    Check for SELinux AVC denials.

    Preconditions:
      - SELinux must be in permissive mode
      - auditd must be running

    Known AVCs from irqbalance, insights-client, and subscription-manager are ignored.
    AVCs in permissive mode are ignored.

    If relevant_keywords is provided(cloudx services), only AVCs matching those keywords cause failure.
    """

    with host.sudo():
        # Check SELinux mode
        selinux_mode = host.run("getenforce").stdout.strip().lower()
        assert selinux_mode == "permissive", f"SELinux is not in permissive mode: {selinux_mode}"

        # Check auditd status
        auditd_status = host.run("systemctl is-active auditd").stdout.strip().lower()
        assert auditd_status == "active", "auditd is not running; cannot check AVC denials"

        # Run ausearch synchronously to get AVCs since boot
        result = host.run("ausearch -m avc -ts boot 2>&1")
        output = result.stdout.lower()

        # If no AVCs are found, nothing to do (test passes)
        if "no matches" in output or not output.strip():
            return

        # Filter out lines containing ignored services/contexts and permissive AVCs
        ignored_avcs = ["irqbalance", "insights_client_t", "subscription-ma"]
        filtered_lines = [
            line for line in output.splitlines()
            if "permissive=1" not in line
               and all(ignored not in line for ignored in ignored_avcs)
        ]
        filtered_output = "\n".join(filtered_lines).strip()

        # If relevant keywords are provided, check for them
        if relevant_keywords:
            for kw in relevant_keywords:
                if kw.lower() in filtered_output:
                    assert False, f"AVC denial related to '{kw}' found:\n{filtered_output}"

        else:
            # If any AVCs remain after filtering, fail
            if filtered_output:
                assert False, f"Unexpected AVC denials found:\n{filtered_output}"
