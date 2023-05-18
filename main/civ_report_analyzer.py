import json
import re

from argparse import ArgumentParser, RawTextHelpFormatter

parser = ArgumentParser(formatter_class=RawTextHelpFormatter)

parser.add_argument('-r', '--report-file',
                    help='Specify the path of a JSON report file that resulted from a CIV test run.',
                    required=True)
parser.add_argument('-o', '--output-file',
                    help='Specify the file path of the analysis file to be stored as plain text with the chosen format.',
                    required=False)
parser.add_argument('-f', '--format',
                    help='(Optional) Specify in which format the analysis should be printed to stdout.\n'
                         'Supported values are:\n'
                         '\t- cli: Outputs a cli-alike analysis\n'
                         '\t- table: Outputs the analysis with rows in tabulated format\n'
                         '\t- jira: Outputs the analysis formatted with Jira markup syntax\n',
                    default='cli',
                    required=False)

spaced_indentation = ' ' * 8


def get_failed_tests_analysis(data):
    test_results = data['tests']

    analysis = {}
    for test in test_results:
        if test['outcome'] == 'failed':
            test_name = test['keywords'][0].split('[')[0]
            error_message = test['call']['crash']['message'].split('\n')[0]

            if test_name in analysis:
                if error_message in analysis[test_name]:
                    analysis[test_name][error_message] += 1
                else:
                    analysis[test_name][error_message] = 1
            else:
                analysis[test_name] = {error_message: 1}

    return analysis


def get_formatted_analysis(report_data, format):
    summary = get_tests_summary(report_data)
    analysis = get_failed_tests_analysis(report_data)
    test_environment = report_data['environment']

    if format == 'table':
        formatted_analysis = get_analysis_as_spreadsheet_table(summary, analysis, test_environment)
    elif format == 'jira':
        formatted_analysis = get_analysis_as_jira_markup(summary, analysis)
    else:
        formatted_analysis = get_analysis_as_cli(summary, analysis)

    return '\n'.join(formatted_analysis)


def get_tests_summary(data):
    summary_data = data['summary']

    passed_total = summary_data['passed']
    failed_total = summary_data['failed'] if 'failed' in summary_data else 0

    failed_and_passed_total = passed_total + failed_total

    success_ratio = round((passed_total * 100 / failed_and_passed_total), 2)

    return {
        'passed_total': passed_total,
        'failed_total': failed_total,
        'failed_and_passed_total': failed_and_passed_total,
        'success_ratio': success_ratio
    }


def get_analysis_as_cli(summary, analysis):
    summary_lines = [
        '-' * 100,
        f"Total passed:\t{summary['passed_total']}",
        f"Total failed:\t{summary['failed_total']}",
        f"Success ratio:\t{summary['success_ratio']}%",
        '-' * 100
    ]

    rows = summary_lines

    for test_case, error_data in analysis.items():
        for err_msg, count in error_data.items():
            rows.append(f'{test_case} - {count} time(s):')
            rows.append('\t' + __parse_error_message(err_msg).replace('\n', f'\n{spaced_indentation}'))

        rows.append('-' * 100)

    return rows


def __parse_error_message(error_message):
    regex_error_generic = re.compile(r'(?:(?:AssertionError|Failed): (.*))')
    regex_error_command = re.compile(
        r"Unexpected exit code \d+ for CommandResult\(command=b?(?P<command>['|\"]?.*['|\"]?), "
        r"exit_status=(?P<exit_status>\d+), stdout=b?(?P<stdout>['|\"]?.*['|\"]?), "
        r"stderr=b?(?P<stderr>['|\"]?.*['|\"]?)\)"
    )

    extracted_message = error_message

    result = re.findall(regex_error_generic, error_message)
    if result:
        extracted_message = result[0]

        result = re.match(regex_error_command, extracted_message)
        if result:
            error_details = result.groupdict()

            composed_error_message = []
            for key, value in error_details.items():
                formatted_value = value.replace(r'\n\n', '\n')
                formatted_value = formatted_value.replace(r"\n", "\n")
                formatted_value = formatted_value.replace("\n\"", "\"")
                formatted_value = formatted_value.replace("\n'", "\'")
                formatted_value = formatted_value.replace("\"", '\"\"')

                composed_error_message.append(f'{key}: {formatted_value.strip()}')

            extracted_message = '\n\n'.join(composed_error_message)

    return extracted_message


def get_analysis_as_jira_markup(summary, analysis):
    summary_lines = [
        '-' * 4,
        f"Total passed:\t{summary['passed_total']}",
        f"Total failed:\t{summary['failed_total']}",
        f"Success ratio:\t{summary['success_ratio']}%",
        '-' * 4
    ]

    rows = summary_lines

    for test_case, error_data in analysis.items():
        for err_msg, count in error_data.items():
            rows.append(
                f'h4. {test_case} - {count} failure(s): ' + '{code:java}' + __parse_error_message(err_msg) + '{code}'
            )

    return rows


def get_analysis_as_spreadsheet_table(summary, analysis, test_environment):
    default_test_owner = 'Jenkins'
    default_status = 'Not Started'
    default_rerun_value = 'FALSE'
    default_delimiter = '\t'

    jenkins_url = '=HYPERLINK("{0}/Report", "{1}")'.format(test_environment['BUILD_URL'], 'Jenkins Report')

    summary_lines = [
        "\t".join(['Total passed:', f"{summary['passed_total']}", '', '', '', 'Pub Task']),
        "\t".join(['Total failed:', str(summary['failed_total']), '', '', 'Jenkins Report (rerun)', jenkins_url]),
        "\t".join(['Success ratio:', f"{summary['success_ratio']}%"])
    ]

    rows = summary_lines

    for test_case, error_data in analysis.items():
        for err_msg, count in error_data.items():
            formatted_err_msg = __parse_error_message(err_msg)

            if '\n' in formatted_err_msg:
                formatted_err_msg.replace("\"", '\"\"')
                formatted_err_msg = f"\"{formatted_err_msg}\""

            row_details = [
                test_case,
                default_test_owner,
                default_status,
                str(count),
                default_rerun_value,
                formatted_err_msg
            ]

            rows.append(default_delimiter.join(row_details))

    return rows


if __name__ == '__main__':
    args = parser.parse_args()

    with open(args.report_file) as f:
        report_data = json.load(f)

    if 'failed' not in report_data['summary']:
        print('Congratulations! No test failures found.')
        exit(0)

    formatted_analysis = get_formatted_analysis(report_data, format=args.format)

    print(formatted_analysis)

    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(formatted_analysis)
