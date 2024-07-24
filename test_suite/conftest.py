import os
import re
import time

import pytest
import requests
from packaging import version
from py.xml import html
from pytest_html import extras
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from test_suite.generic import helpers

from lib import test_lib


def __get_host_info(host):
    host_info = {}
    host_info['distro'] = host.system_info.distribution
    host_info['version'] = version.parse(host.system_info.release)
    host_info['distro_version'] = f'{host_info["distro"]}{host_info["version"]}'
    host_info['skip_message'] = f'This test doesn\'t apply to {host_info["distro_version"]}'
    return host_info


def __parse_distro_version(distro_version):
    res = re.search(r'\d+(\.\d+)?', distro_version)
    if res:
        return version.parse(res.group(0))


def __check_wait_marker(request):
    # Check if test needs to wait before being run
    wait_marker = request.node.get_closest_marker('wait')

    if wait_marker:
        seconds_to_wait = int(wait_marker.args[0])
        print(f'Waiting {seconds_to_wait} seconds before running test...')
        time.sleep(seconds_to_wait)


def __check_exclude_on_marker(request, host_info):
    exclude_on_marker = request.node.get_closest_marker('exclude_on')
    if not exclude_on_marker:
        return

    exclude_on_marker_list = exclude_on_marker.args[0]

    if host_info['distro'] in exclude_on_marker_list or host_info['distro_version'] in exclude_on_marker_list:
        pytest.skip(host_info['skip_message'])

    # Check if the current distro_version matches any condition of a marker element
    # with a relational operator. If it does, do not run the test
    for item in exclude_on_marker_list:
        if host_info['distro'] in item:
            item_distro_version = __parse_distro_version(item)

            if item[0] == '<' and host_info['version'] < item_distro_version:
                pytest.skip(host_info['skip_message'])

            if item[0] == '>' and host_info['version'] > item_distro_version:
                pytest.skip(host_info['skip_message'])

            if item[1] == '=' and host_info['version'] == item_distro_version:
                pytest.skip(host_info['skip_message'])


def __check_run_on_marker(request, host_info):
    run_on_marker = request.node.get_closest_marker('run_on')
    if not run_on_marker:
        pytest.fail('All test cases have to be marked with the "run_on" marker. Check README.md for more information.')

    run_on_marker_list = run_on_marker.args[0]

    if host_info['distro'] in run_on_marker_list or \
            host_info['distro_version'] in run_on_marker_list or \
            'all' in run_on_marker_list:
        return

    # Check if the current distro_version matches at least one condition of a marker element
    # with a relational operator. If no element matches, we do not run the test
    for item in run_on_marker_list:
        if host_info['distro'] in item:
            item_distro_version = __parse_distro_version(item)

            if item[0] == '<' and host_info['version'] < item_distro_version:
                return

            if item[0] == '>' and host_info['version'] > item_distro_version:
                return

            if item[1] == '=' and host_info['version'] == item_distro_version:
                return

    pytest.skip(host_info['skip_message'])


def __check_jira_skip_marker(request):
    jira_skip_marker = request.node.get_closest_marker('jira_skip')
    if not jira_skip_marker:
        return

    jira_skip_marker_list = jira_skip_marker.args[0]

    s = requests.Session()
    retries = Retry(total=3, backoff_factor=3)
    s.mount('https://issues.redhat.com', HTTPAdapter(max_retries=retries))

    JIRA_PAT = os.getenv('JIRA_PAT')
    if not JIRA_PAT:
        exit('JIRA_PAT was not found')

    headers = {'Authorization': f'Bearer {os.getenv("JIRA_PAT")}'}
    endpoint_base = 'https://issues.redhat.com/rest/api/2/issue/'

    for ticket_id in jira_skip_marker_list:
        endpoint = endpoint_base + ticket_id
        res = s.get(endpoint, headers=headers)

        if res.status_code != 200:
            print(f'ERROR: (JIRA API) - Could not check Jira ticket {ticket_id}\n'
                  f'API request error code {res.status_code}\n'
                  'Running test as the status cannot be checked')

        status = res.json()['fields']['status']['name']
        if status != 'Closed':
            pytest.skip(f'Test skipped because Jira ticket {ticket_id} is not Closed yet')
        else:
            print(
                f'WARNING: Jira ticket {ticket_id} is already closed. Please remove it from the marker and put it in the docstring')


@pytest.fixture(autouse=True, scope='function')
def check_markers(host, request):
    host_info = __get_host_info(host)

    __check_wait_marker(request)
    __check_exclude_on_marker(request, host_info)
    __check_run_on_marker(request, host_info)
    __check_jira_skip_marker(request)


@pytest.fixture
def rhel_sap_only(host):
    if not test_lib.is_rhel_sap(host):
        pytest.skip('Image is not SAP RHEL')


@pytest.fixture
def rhel_high_availability_only(host):
    if not test_lib.is_rhel_high_availability(host):
        pytest.skip('Image is not HA (High Availability)')


@pytest.fixture
def rhel_atomic_only(host):
    if not test_lib.is_rhel_atomic_host(host):
        pytest.skip('Image is not atomic RHEL')


@pytest.fixture(scope='function', autouse=True)
def instance_data(host):
    values_to_find = [host.backend.hostname]
    values_to_find.extend(host.addr(host.backend.hostname).ipv4_addresses)

    return helpers.__get_instance_data_from_json(
        key_to_find='address', values_to_find=values_to_find, path=helpers.INSTANCES_JSON_PATH
    )


@pytest.fixture(autouse=True)
def html_report_links(extra, host, instance_data):
    extra.append(extras.json(instance_data, 'Instance JSON'))

    link_name = f'{host.system_info.distribution}-{host.system_info.release}'
    extra.append(extras.json(vars(host.system_info)['sysinfo'], name=link_name))


def pytest_configure(config):
    pytest.markers_used = config.getoption('-m')


def pytest_html_report_title(report):
    report.title = 'Cloud Image Validation Report'


def pytest_html_results_summary(prefix, summary, postfix):
    prefix.extend([html.a('GitHub: https://github.com/osbuild/cloud-image-val',
                          href='https://github.com/osbuild/cloud-image-val')])

    if pytest.markers_used:
        postfix.extend([html.h4(f'Markers used: {pytest.markers_used}')])


def pytest_html_results_table_header(cells):
    del cells[1]

    cells.insert(1, html.th('Test_Case', class_='sortable', **{'data-column-type': 'test_case'}))
    cells.insert(2, html.th('Description', **{'data-column-type': 'description'}))
    cells.insert(3, html.th('Image', class_='sortable', **{'data-column-type': 'image'}))


def pytest_html_results_table_row(report, cells):
    del cells[1]

    cells.insert(1, html.td(getattr(report, 'test_case', '')))
    cells.insert(2, html.td(getattr(report, 'description', ''),
                            style='white-space:pre-line; word-wrap:break-word'))
    cells.insert(3, html.td(getattr(report, 'image', '')))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    # Set the test cases 'Duration' format
    setattr(report, 'duration_formatter', '%S.%f sec')

    # Fill 'Test Case' column
    report.test_case = f'{str(item.parent.name)}::{str(item.function.__name__)}'

    # Fill 'Description' column
    description_text = __truncate_text(str(item.function.__doc__), 120)
    report.description = description_text

    # Fill 'Image' column
    if 'instance_data' in item.funcargs:
        instance = item.funcargs['instance_data']
        if instance:
            image_ref = instance['image']
            report.image = str(image_ref)


def __truncate_text(text, max_chars):
    if len(text) > max_chars:
        text = f'{text[:max_chars]} [...]'
    return text
