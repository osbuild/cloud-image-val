import json
import time
import pytest
import re

from py.xml import html
from pytest_html import extras

from lib import test_lib


@pytest.fixture(autouse=True, scope='function')
def check_markers(host, request):
    skip_message = "This test doesn't apply to {distro_version}"

    def parse_distro_version(distro_version):
        return float(re.findall(r"\d+(\.\d+)?", distro_version)[0])

    # Check if test needs to wait before being run
    wait_marker = request.node.get_closest_marker('wait')
    if wait_marker:
        seconds_to_wait = int(wait_marker.args[0])
        print(f'Waiting {seconds_to_wait} seconds before running test...')
        time.sleep(seconds_to_wait)

    # This part checks the list of combinations of distro-version each test has.
    # If the host doesn't meet any of the combinations, the test will be skipped.
    run_on_marker = request.node.get_closest_marker('run_on')
    exclude_on_marker = request.node.get_closest_marker('exclude_on')
    if not run_on_marker and not exclude_on_marker:
        pytest.fail('All test cases have to be marked with at least "run_on" \
                    or "exlude_on" marker')

    supported_distros_and_versions = [
        'fedora', 'fedora34', 'fedora35', 'fedora36',
        'rhel', 'rhel7.9', 'rhel8.4', 'rhel8.5', 'rhel8.6', 'rhel9.0',
        'centos', 'centos8', 'centos9'
    ]

    host_distro = host.system_info.distribution
    host_version = float(host.system_info.release)
    distro_version = f'{host_distro}{host_version}'

    # Skip the test if the distro is explicitly excluded
    if exclude_on_marker:
        exclude_on_marker_list = exclude_on_marker.args[0]
        if host_distro in exclude_on_marker_list \
                or distro_version in exclude_on_marker_list:
            pytest.skip(skip_message.format(distro_version=distro_version))
        else:
            for item in exclude_on_marker_list:
                if host_distro in item and item[0] == '<':
                    if host_version < parse_distro_version(item):
                        pytest.skip(skip_message.format(distro_version=distro_version))
                    else:
                        return
                if host_distro in item and item[0] == '>':
                    if host_version > parse_distro_version(item):
                        pytest.skip(skip_message.format(distro_version=distro_version))
                    else:
                        return

    # If there is no run_on_marker and distro is not excluded execute supported
    # tests
    if not run_on_marker:
        if distro_version in supported_distros_and_versions:
            return
        pytest.fail(f"{distro_version} is not supported distro/version")

    run_on_marker_list = run_on_marker.args[0]

    if 'all' in run_on_marker_list:
        return

    # Make the test fail if one or more items in "run_on" marker are incorrect
    if not set(run_on_marker_list) <= set(supported_distros_and_versions):
        pytest.fail('One or more run_on markers are not supported')

    if host_distro in run_on_marker_list \
            or distro_version in run_on_marker_list:
        return
    else:
        pytest.skip(skip_message.format(distro_version=distro_version))


@pytest.mark.run_on(['rhel'])
@pytest.fixture
def rhel_sap_only(host):
    if not test_lib.is_rhel_sap(host):
        pytest.skip('Image is not SAP RHEL')


@pytest.mark.run_on(['rhel'])
@pytest.fixture
def rhel_high_availability_only(host):
    if not test_lib.is_rhel_high_availability(host):
        pytest.skip('Image is not HA (High Availability)')


@pytest.mark.run_on(['rhel'])
@pytest.fixture
def rhel_atomic_only(host):
    if not test_lib.is_rhel_atomic_host(host):
        pytest.skip('Image is not atomic RHEL')


@pytest.fixture(autouse=True)
def instance_data(host):
    return __get_instance_data_from_json(key_to_find='public_dns',
                                         value_to_find=host.backend.hostname)


def __get_instance_data_from_json(key_to_find, value_to_find):
    # TODO: Pass this hardcoded path to a config file and read from there.
    with open('/tmp/instances.json', 'r') as f:
        instances_json_data = json.load(f)
    for instance in instances_json_data.values():
        if key_to_find in instance.keys() and instance[key_to_find] == value_to_find:
            return instance


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

    cells.insert(1, html.th('Test Case', class_='sortable'))
    cells.insert(2, html.th('Description'))
    cells.insert(3, html.th('Image Reference', class_='sortable'))


def pytest_html_results_table_row(report, cells):
    del cells[1]

    cells.insert(1, html.td(getattr(report, 'test_case', '')))
    cells.insert(2, html.td(getattr(report, 'description', ''),
                            style='white-space:pre-line; word-wrap:break-word'))
    cells.insert(3, html.td(getattr(report, 'image_reference', '')))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    # Set the test cases "Duration" format
    setattr(report, 'duration_formatter', '%S.%f sec')

    # Fill "Test Case" column
    report.test_case = f'{str(item.parent.name)}::{str(item.function.__name__)}'

    # Fill "Description" column
    description_text = __truncate_text(str(item.function.__doc__), 120)
    report.description = description_text

    # Fill "Image Reference" column
    if 'instance_data' in item.funcargs:
        instance = item.funcargs['instance_data']
        image_ref = instance['ami'] if 'ami' in instance else instance['image']
        report.image_reference = str(image_ref)


def __truncate_text(text, max_chars):
    if len(text) > max_chars:
        text = f'{text[:max_chars]} [...]'
    return text
