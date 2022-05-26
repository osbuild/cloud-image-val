import json
import pytest

from py.xml import html
from pytest_html import extras

from lib import test_lib


@pytest.fixture
def rhel_only(host):
    if host.system_info.distribution != 'rhel':
        pytest.skip('Image is not RHEL')


@pytest.fixture
def rhel_sap_only(host, rhel_only):
    if not test_lib.is_rhel_sap(host):
        pytest.skip('Image is not SAP RHEL')


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
