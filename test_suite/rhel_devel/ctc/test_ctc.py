import pytest
from lib import console_lib
from test_suite.rhel_devel import run_cloudx_components_testing

"""
CTC (Comprehensive Tests Cycle) refers to the RHEL testing phase
were we thoroughly test our components on a specified RHEL version.
There is also CTC2 which is another round in a later stage of SDLC.
"""


@pytest.mark.ctc
@pytest.mark.run_on(['all'])
class TestsComprehensiveTestsCycle:
    def test_components(self, host):
        console_lib.print_divider('Testing CloudX-owned components...')
        assert run_cloudx_components_testing.main()
