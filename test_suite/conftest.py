import pytest
from py.xml import html
import json


@pytest.fixture
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


def pytest_html_results_table_header(cells):
    cells.insert(2, html.th('Description', class_='sortable'))
    cells.insert(3, html.th('Error Message', class_='sortable'))


def pytest_html_results_table_row(report, cells):
    cells.insert(2, html.td(getattr(report, 'description', '')))
    cells.insert(3, html.td(getattr(report, 'error_message', '')))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    # Fill "Description" column
    report.description = str(item.function.__doc__)

    # Fill "Error Message" column
    setattr(item, 'rep_' + report.when, report)
    report.error_message = str(call.excinfo.value) if call.excinfo else ''
    if report.when == 'teardown':
        max_msg_length = 200
        message = item.rep_call.error_message.split(' assert ')[0]

        if len(message) > max_msg_length:
            message = f'{message[:max_msg_length]} [...]'

        report.error_message = message
