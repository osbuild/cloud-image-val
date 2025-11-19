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
    Enforce SELinux rules:
      - SAP HANA (is_rhel_saphaus) → SELinux must be permissive → check AVCs
      - Non-SAP → SELinux must be enforcing → no AVC checks
    """
    import pdb
    pdb.set_trace()
    with host.sudo():
        is_sap = test_lib.is_rhel_saphaus(host)
        selinux_mode = host.run("getenforce").stdout.strip().lower()

        # Non-SAP → SELinux must be enforcing and we skip AVC checks
        if not is_sap:
            assert selinux_mode == "enforcing", \
                f"Expected SELinux enforcing on non-SAP, got {selinux_mode}"
            return

        # SAP → must be permissive
        assert selinux_mode == "permissive", \
            f"Expected SELinux permissive on SAP, got {selinux_mode}"

        # SAP → check AVCs
        auditd_running = host.run("systemctl is-active auditd").stdout.strip().lower()
        assert auditd_running == "active", "auditd must be running to check AVCs"

        result = host.run("ausearch -m avc -ts recent 5min 2>/dev/null")
        output = result.stdout

        if not output or "no matches" in output.lower():
            return

        ignored_keywords = ["irqbalance", "insights_client_t", "subscription-ma"]

        # Normalize to lowercase for consistent comparisons
        output_lines = output.lower().splitlines()

        filtered = [
            line for line in output_lines
            if "permissive=1" not in line
            and not any(ignored in line for ignored in ignored_keywords)
        ]

        if not filtered:
            return

        filtered_output = "\n".join(filtered).strip()

        if relevant_keywords:
            for kw in relevant_keywords:
                if kw.lower() in filtered_output:
                    assert False, f"AVC related to '{kw}':\n{filtered_output}"
        else:
            assert False, f"Unexpected AVCs:\n{filtered_output}"
