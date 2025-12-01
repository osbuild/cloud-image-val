import os
import json

from lib import test_lib

INSTANCES_JSON_PATH = os.environ['CIV_INSTANCES_JSON']


def __get_instance_data_from_json(key_to_find, values_to_find, path=INSTANCES_JSON_PATH):
    with open(path, 'r') as f:
        instances_json_data = json.load(f)
    for instance in instances_json_data.values():
        if key_to_find in instance.keys() and instance[key_to_find] in values_to_find:
            return instance


def check_avc_denials(host, relevant_keywords=None):
    """
    Check SELinux AVC denials.

    - SAP: expected to run in permissive mode → check AVCs, ignoring known noisy AVCs.
    - Non-SAP: expected to run in enforcing mode → check AVCs, ignoring known noisy AVCs.
    - Only AVCs matching `relevant_keywords` (if provided) will fail the test.
    """
    with host.sudo():
        is_sap = test_lib.is_rhel_saphaus(host)
        selinux_mode = host.run("getenforce").stdout.strip().lower()

        # Validate SELinux mode
        expected_mode = "permissive" if is_sap else "enforcing"
        assert selinux_mode == expected_mode, \
            f"Expected SELinux {expected_mode} on {'SAP' if is_sap else 'Non-SAP'}, got {selinux_mode}"

        # Ensure auditd is running
        auditd_running = host.run("systemctl is-active auditd").stdout.strip().lower()
        assert auditd_running == "active", "auditd must be running to check AVCs"

        # Get all AVCs
        result = host.run("timeout 10 ausearch -m avc 2>&1")
        output = result.stdout

        if not output or "no matches" in output.lower():
            return

        ignored_keywords = ["insights_client_t", "subscription-ma"]

        output_lines = output.lower().splitlines()

        filtered = [
            line for line in output_lines
            if "permissive=1" not in line  # skip permissive-mode AVCs
            and not any(ignored in line for ignored in ignored_keywords)
        ]

        if not filtered:
            return

        filtered_output = "\n".join(filtered).strip()

        # Check relevant keywords if provided, otherwise report all filtered AVCs
        if relevant_keywords:
            relevant_found = [
                line for line in filtered
                for kw in relevant_keywords
                if kw.lower() in line
            ]
            if relevant_found:
                filtered_relevant_output = "\n".join(relevant_found)
                assert False, f"Relevant AVC denials found:\n{filtered_relevant_output}"
        else:
            # Fail with summary of all filtered AVCs
            assert False, f"Unexpected AVC denials:\n{filtered_output}"
