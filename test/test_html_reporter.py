import pytest

from result.html_reporter import HTMLReporter


class TestHTMLReporter:
    test_junit_report_path = '/test/path/to/junit/report.xml'

    @pytest.fixture
    def html_reporter(self):
        return HTMLReporter(self.test_junit_report_path)

    def test_generate_report(self, mocker, html_reporter):
        test_destination_path = 'test/path/to/report.html'
        mock_os_system = mocker.patch('os.system')
        mock_print = mocker.patch('builtins.print')

        html_reporter.generate_report(test_destination_path)

        mock_os_system.assert_called_once_with(f'junit2html {self.test_junit_report_path} '
                                               f'--report-matrix {test_destination_path}')
        mock_print.assert_called_once_with(f'HTML report generated: {test_destination_path}')
