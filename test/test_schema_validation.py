import os
import subprocess
import tempfile

import pytest
from lxml import etree


XSD_PATH = os.path.join(os.path.dirname(__file__), '..', 'schemas', 'junit.xsd')


@pytest.fixture
def xsd_schema():
    return etree.XMLSchema(etree.parse(XSD_PATH))


VALID_JUNIT_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="pytest" errors="0" failures="1" skipped="1" tests="3"
               time="0.042" timestamp="2026-08-13T13:58:14.911738" hostname="fedora">
        <testcase classname="test_sample" name="test_pass" time="0.001" />
        <testcase classname="test_sample" name="test_fail" time="0.002">
            <failure message="AssertionError: expected failure">
                assert False
            </failure>
        </testcase>
        <testcase classname="test_sample" name="test_skip" time="0.000">
            <skipped type="pytest.skip" message="not applicable" />
        </testcase>
    </testsuite>
</testsuites>
"""

VALID_JUNIT_WITH_ERROR = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="pytest" errors="1" failures="0" skipped="0" tests="1"
               time="0.010" timestamp="2026-08-13T14:00:00" hostname="ci-runner">
        <testcase classname="test_err" name="test_runtime_error" time="0.005">
            <error message="RuntimeError: boom" type="RuntimeError">
                Traceback ...
            </error>
        </testcase>
        <system-out>some stdout</system-out>
        <system-err>some stderr</system-err>
    </testsuite>
</testsuites>
"""

VALID_EMPTY_SUITE = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="empty" tests="0" errors="0" failures="0" time="0.000">
    </testsuite>
</testsuites>
"""

MALFORMED_MISSING_NAME = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite errors="0" failures="0" tests="1" time="0.001">
        <testcase classname="test_x" name="test_a" time="0.001" />
    </testsuite>
</testsuites>
"""

MALFORMED_MISSING_TESTCASE_NAME = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="suite" errors="0" failures="0" tests="1" time="0.001">
        <testcase classname="test_x" time="0.001" />
    </testsuite>
</testsuites>
"""

MALFORMED_EXTRA_ELEMENT_IN_TESTCASE = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="suite" errors="0" failures="0" tests="1" time="0.001">
        <testcase classname="test_x" name="test_a" time="0.001">
            <bogus>unexpected element</bogus>
        </testcase>
    </testsuite>
</testsuites>
"""

MALFORMED_EXTRA_ELEMENT_IN_TESTSUITE = """\
<?xml version="1.0" encoding="utf-8"?>
<testsuites>
    <testsuite name="suite" errors="0" failures="0" tests="1" time="0.001">
        <unknown-element />
        <testcase classname="test_x" name="test_a" time="0.001" />
    </testsuite>
</testsuites>
"""

MALFORMED_NOT_XML = "this is not xml at all"


class TestJunitXsd:

    def test_xsd_is_valid_schema(self):
        etree.XMLSchema(etree.parse(XSD_PATH))

    def test_valid_junit_xml(self, xsd_schema):
        doc = etree.fromstring(VALID_JUNIT_XML.encode())
        assert xsd_schema.validate(doc)

    def test_valid_junit_with_error_and_system_output(self, xsd_schema):
        doc = etree.fromstring(VALID_JUNIT_WITH_ERROR.encode())
        assert xsd_schema.validate(doc)

    def test_valid_empty_suite(self, xsd_schema):
        doc = etree.fromstring(VALID_EMPTY_SUITE.encode())
        assert xsd_schema.validate(doc)

    def test_invalid_missing_testsuite_name(self, xsd_schema):
        doc = etree.fromstring(MALFORMED_MISSING_NAME.encode())
        assert not xsd_schema.validate(doc)

    def test_invalid_missing_testcase_name(self, xsd_schema):
        doc = etree.fromstring(MALFORMED_MISSING_TESTCASE_NAME.encode())
        assert not xsd_schema.validate(doc)

    def test_invalid_extra_element_in_testcase(self, xsd_schema):
        doc = etree.fromstring(MALFORMED_EXTRA_ELEMENT_IN_TESTCASE.encode())
        assert not xsd_schema.validate(doc)

    def test_invalid_extra_element_in_testsuite(self, xsd_schema):
        doc = etree.fromstring(MALFORMED_EXTRA_ELEMENT_IN_TESTSUITE.encode())
        assert not xsd_schema.validate(doc)

    def test_invalid_not_xml(self):
        with pytest.raises(etree.XMLSyntaxError):
            etree.fromstring(MALFORMED_NOT_XML.encode())

    def test_pytest_junit_xml_output(self, xsd_schema):
        test_file = os.path.join(os.path.dirname(__file__), '_sample_for_junit.py')
        with open(test_file, 'w') as f:
            f.write("def test_pass(): assert True\n")
        try:
            with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp:
                xml_path = tmp.name
            subprocess.run(
                ['pytest', test_file, f'--junit-xml={xml_path}', '-q',
                 f'--rootdir={os.path.dirname(test_file)}'],
                capture_output=True, check=True
            )
            doc = etree.parse(xml_path)
            assert xsd_schema.validate(doc), xsd_schema.error_log
        finally:
            for p in [test_file, xml_path]:
                if os.path.exists(p):
                    os.unlink(p)
