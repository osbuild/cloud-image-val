import os

import pytest
from lxml import etree

from core.results import (
    MergeResult,
    ResultValidationError,
    get_exit_code,
    merge_results,
    validate_junit_xml,
)


VALID_SINGLE_SUITE = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="pytest" errors="0" failures="0" skipped="0" tests="2"
               time="0.050" timestamp="2026-08-18T10:00:00" hostname="host1">
        <testcase classname="test_generic" name="test_pass_1" time="0.020" />
        <testcase classname="test_generic" name="test_pass_2" time="0.030" />
    </testsuite>
</testsuites>
"""

VALID_WITH_FAILURE = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="pytest" errors="0" failures="1" skipped="0" tests="2"
               time="0.040" timestamp="2026-08-18T10:00:00" hostname="host1">
        <testcase classname="test_generic" name="test_pass" time="0.010" />
        <testcase classname="test_generic" name="test_fail" time="0.030">
            <failure message="assert False">assert False</failure>
        </testcase>
    </testsuite>
</testsuites>
"""

VALID_WITH_ERROR = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="pytest" errors="1" failures="0" skipped="0" tests="1"
               time="0.010" timestamp="2026-08-18T10:00:00" hostname="host1">
        <testcase classname="test_generic" name="test_err" time="0.010">
            <error message="RuntimeError" type="RuntimeError">traceback</error>
        </testcase>
    </testsuite>
</testsuites>
"""

VALID_WITH_SKIP = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="pytest" errors="0" failures="0" skipped="1" tests="1"
               time="0.001" timestamp="2026-08-18T10:00:00" hostname="host1">
        <testcase classname="test_generic" name="test_skip" time="0.001">
            <skipped message="not applicable" />
        </testcase>
    </testsuite>
</testsuites>
"""

VALID_EMPTY_SUITE = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="pytest" errors="0" failures="0" skipped="0" tests="0"
               time="0.000" timestamp="2026-08-18T10:00:00" hostname="host1">
    </testsuite>
</testsuites>
"""

VALID_BARE_TESTSUITE = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" errors="0" failures="0" skipped="0" tests="1"
           time="0.010" timestamp="2026-08-18T10:00:00" hostname="host1">
    <testcase classname="test_generic" name="test_a" time="0.010" />
</testsuite>
"""

INVALID_XML = "this is not xml"

INVALID_SCHEMA = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite errors="0" failures="0" tests="1" time="0.001">
        <testcase classname="test_x" name="test_a" time="0.001" />
    </testsuite>
</testsuites>
"""


def _write_xml(tmp_path: str, filename: str, content: str) -> str:
    path = os.path.join(tmp_path, filename)
    with open(path, 'w') as f:
        f.write(content)
    return path


class TestValidateJunitXml:

    def test_valid_file(self, tmp_path):
        path = _write_xml(str(tmp_path), 'valid.xml', VALID_SINGLE_SUITE)
        assert validate_junit_xml(path) is True

    def test_valid_bare_testsuite(self, tmp_path):
        path = _write_xml(str(tmp_path), 'bare.xml', VALID_BARE_TESTSUITE)
        assert validate_junit_xml(path) is True

    def test_malformed_xml_raises(self, tmp_path):
        path = _write_xml(str(tmp_path), 'bad.xml', INVALID_XML)
        with pytest.raises(ResultValidationError, match="Malformed XML"):
            validate_junit_xml(path)

    def test_schema_violation_raises(self, tmp_path):
        path = _write_xml(str(tmp_path), 'invalid.xml', INVALID_SCHEMA)
        with pytest.raises(ResultValidationError, match="XSD validation failed"):
            validate_junit_xml(path)

    def test_nonexistent_file_raises(self):
        with pytest.raises(OSError):
            validate_junit_xml('/nonexistent/path.xml')


class TestMergeResults:

    def test_single_file(self, tmp_path):
        src = _write_xml(str(tmp_path), 'result.xml', VALID_SINGLE_SUITE)
        out = str(tmp_path / 'merged.xml')

        result = merge_results([src], out)

        assert result.total_tests == 2
        assert result.failures == 0
        assert result.errors == 0
        assert result.skipped == 0
        assert os.path.exists(out)

    def test_multiple_files(self, tmp_path):
        src1 = _write_xml(str(tmp_path), 'r1.xml', VALID_SINGLE_SUITE)
        src2 = _write_xml(str(tmp_path), 'r2.xml', VALID_WITH_FAILURE)
        out = str(tmp_path / 'merged.xml')

        result = merge_results([src1, src2], out)

        assert result.total_tests == 4
        assert result.failures == 1
        assert result.errors == 0

    def test_merged_output_is_valid_xml(self, tmp_path):
        src1 = _write_xml(str(tmp_path), 'r1.xml', VALID_SINGLE_SUITE)
        src2 = _write_xml(str(tmp_path), 'r2.xml', VALID_WITH_FAILURE)
        out = str(tmp_path / 'merged.xml')

        merge_results([src1, src2], out)

        doc = etree.parse(out)
        root = doc.getroot()
        assert root.tag == "testsuites"
        assert len(root.findall("testsuite")) == 2

    def test_instance_labels_prefix_suite_names(self, tmp_path):
        src1 = _write_xml(str(tmp_path), 'r1.xml', VALID_SINGLE_SUITE)
        src2 = _write_xml(str(tmp_path), 'r2.xml', VALID_WITH_FAILURE)
        out = str(tmp_path / 'merged.xml')

        merge_results([src1, src2], out, instance_labels=['instance-1', 'instance-2'])

        doc = etree.parse(out)
        names = [s.get("name") for s in doc.getroot().findall("testsuite")]
        assert names == ['instance-1.pytest', 'instance-2.pytest']

    def test_instance_labels_length_mismatch_raises(self, tmp_path):
        src = _write_xml(str(tmp_path), 'r1.xml', VALID_SINGLE_SUITE)
        out = str(tmp_path / 'merged.xml')

        with pytest.raises(ValueError, match="instance_labels must match"):
            merge_results([src], out, instance_labels=['a', 'b'])

    def test_empty_suite(self, tmp_path):
        src = _write_xml(str(tmp_path), 'empty.xml', VALID_EMPTY_SUITE)
        out = str(tmp_path / 'merged.xml')

        result = merge_results([src], out)

        assert result.total_tests == 0
        assert result.failures == 0

    def test_bare_testsuite_without_wrapper(self, tmp_path):
        src = _write_xml(str(tmp_path), 'bare.xml', VALID_BARE_TESTSUITE)
        out = str(tmp_path / 'merged.xml')

        result = merge_results([src], out)

        assert result.total_tests == 1
        doc = etree.parse(out)
        assert doc.getroot().tag == "testsuites"

    def test_invalid_file_raises(self, tmp_path):
        src = _write_xml(str(tmp_path), 'bad.xml', INVALID_XML)
        out = str(tmp_path / 'merged.xml')

        with pytest.raises(ResultValidationError, match="Malformed XML"):
            merge_results([src], out)

    def test_schema_violation_raises(self, tmp_path):
        src = _write_xml(str(tmp_path), 'invalid.xml', INVALID_SCHEMA)
        out = str(tmp_path / 'merged.xml')

        with pytest.raises(ResultValidationError, match="XSD validation failed"):
            merge_results([src], out)

    def test_empty_paths_list(self, tmp_path):
        out = str(tmp_path / 'merged.xml')

        result = merge_results([], out)

        assert result.total_tests == 0
        assert result.failures == 0
        assert os.path.exists(out)

    def test_time_accumulation(self, tmp_path):
        src1 = _write_xml(str(tmp_path), 'r1.xml', VALID_SINGLE_SUITE)
        src2 = _write_xml(str(tmp_path), 'r2.xml', VALID_WITH_FAILURE)
        out = str(tmp_path / 'merged.xml')

        result = merge_results([src1, src2], out)

        assert result.time == 0.09

    def test_mixed_results(self, tmp_path):
        src1 = _write_xml(str(tmp_path), 'r1.xml', VALID_WITH_FAILURE)
        src2 = _write_xml(str(tmp_path), 'r2.xml', VALID_WITH_ERROR)
        src3 = _write_xml(str(tmp_path), 'r3.xml', VALID_WITH_SKIP)
        out = str(tmp_path / 'merged.xml')

        result = merge_results([src1, src2, src3], out)

        assert result.total_tests == 4
        assert result.failures == 1
        assert result.errors == 1
        assert result.skipped == 1


class TestGetExitCode:

    def test_all_pass(self):
        result = MergeResult(total_tests=10, failures=0, errors=0, skipped=0, time=1.0)
        assert get_exit_code(result) == 0

    def test_with_failures(self):
        result = MergeResult(total_tests=10, failures=2, errors=0, skipped=0, time=1.0)
        assert get_exit_code(result) == 1

    def test_with_errors(self):
        result = MergeResult(total_tests=10, failures=0, errors=1, skipped=0, time=1.0)
        assert get_exit_code(result) == 2

    def test_errors_take_precedence_over_failures(self):
        result = MergeResult(total_tests=10, failures=3, errors=1, skipped=0, time=1.0)
        assert get_exit_code(result) == 2

    def test_skipped_only_is_pass(self):
        result = MergeResult(total_tests=5, failures=0, errors=0, skipped=5, time=0.5)
        assert get_exit_code(result) == 0

    def test_empty_result(self):
        result = MergeResult(total_tests=0, failures=0, errors=0, skipped=0, time=0.0)
        assert get_exit_code(result) == 0
