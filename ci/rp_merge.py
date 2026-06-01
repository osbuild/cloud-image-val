#!/usr/bin/env python3
"""
ReportPortal auto-merge script.

Finds all launches sharing a CycleGroup attribute value and merges them
into a single linear launch. Intended to be called from Jenkins after
each regional upload, so that multi-region runs are consolidated.

Usage:
    python3 ci/rp_merge.py \
        --rp-url https://reportportal-cloudx.apps.dno.ocp-hub.prod.psi.redhat.com \
        --project cloudx \
        --token $RP_TOKEN \
        --group-token $CYCLE_GROUP \
        --launch-name "RHEL-10.0" \
        --region "AWS US-GOV"
"""

import argparse
import logging
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="ReportPortal launch auto-merger")
    parser.add_argument("--rp-url", required=True, help="Base ReportPortal URL")
    parser.add_argument("--project", required=True, help="RP project name")
    parser.add_argument("--token", required=True, help="RP API token")
    parser.add_argument("--group-token", required=True, help="CycleGroup attribute value to search by")
    parser.add_argument("--launch-name", required=True, help="Name for the merged launch")
    parser.add_argument("--region", required=True, help="Region label (e.g. 'AWS US-GOV')")
    parser.add_argument("--merge-timeout", type=int, default=30,
                        help="Seconds to wait for launches to finish before merging (default: 30)")
    return parser.parse_args()


def build_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def get_launches_by_group(rp_url, project, headers, group_token):
    url = f"{rp_url}/api/v1/{project}/launch"
    params = {"filter.has.attributeValue": group_token, "page.size": 50}
    try:
        resp = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
        resp.raise_for_status()
        return resp.json().get("content", [])
    except requests.RequestException as e:
        log.error("Failed to fetch launches: %s", e)
        sys.exit(1)


def wait_for_launches(rp_url, project, headers, launch_ids, timeout):
    """Poll until all launches are in a finished state, up to timeout seconds."""
    log.info("Waiting up to %ds for %d launch(es) to finish...", timeout, len(launch_ids))
    deadline = time.time() + timeout
    pending = set(launch_ids)

    while pending and time.time() < deadline:
        time.sleep(5)
        for lid in list(pending):
            url = f"{rp_url}/api/v1/{project}/launch/{lid}"
            try:
                resp = requests.get(url, headers=headers, verify=False, timeout=15)
                resp.raise_for_status()
                status = resp.json().get("status", "")
                if status in ("PASSED", "FAILED", "STOPPED", "INTERRUPTED"):
                    log.info("Launch %s finished with status: %s", lid, status)
                    pending.discard(lid)
            except requests.RequestException as e:
                log.warning("Could not check launch %s status: %s", lid, e)

    if pending:
        log.warning("Timed out waiting for launches: %s — proceeding anyway", pending)


def merge_launches(rp_url, project, headers, launch_ids, launch_name, group_token, region):
    url = f"{rp_url}/api/v1/{project}/launch/merge"
    payload = {
        "ids": launch_ids,
        "name": launch_name,
        "mergeType": "LINEAR",
        "extendSuitesDescription": True,
        "attributes": [
            {"key": "skippedIsNotIssue", "system": True, "value": "true"},
            {"key": "CycleGroup", "value": group_token},
            {"key": "Region", "value": region},
        ],
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=60)
        resp.raise_for_status()
        merged = resp.json()
        log.info("Merged into launch id=%s name='%s'", merged.get("id"), merged.get("name"))
    except requests.RequestException as e:
        log.error("Merge failed: %s", e)
        sys.exit(1)


def main():
    args = parse_args()
    headers = build_headers(args.token)

    log.info("Searching for launches with CycleGroup='%s'", args.group_token)
    launches = get_launches_by_group(args.rp_url, args.project, headers, args.group_token)

    if not launches:
        log.info("No launches found for group '%s' — nothing to merge.", args.group_token)
        sys.exit(0)

    if len(launches) == 1:
        log.info("Only one launch found — no merge needed.")
        sys.exit(0)

    launch_ids = [launch["id"] for launch in launches]
    log.info("Found %d launches to merge: %s", len(launch_ids), launch_ids)

    wait_for_launches(args.rp_url, args.project, headers, launch_ids, args.merge_timeout)
    merge_launches(args.rp_url, args.project, headers, launch_ids, args.launch_name, args.group_token, args.region)


if __name__ == "__main__":
    main()
