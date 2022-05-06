import pytest
from py.xml import html


def pytest_html_results_table_header(cells):
    cells.insert(2, html.th('Description', class_='sortable'))


def pytest_html_results_table_row(report, cells):
    cells.insert(2, html.td(getattr(report, 'description', '')))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    report.description = str(item.function.__doc__)
