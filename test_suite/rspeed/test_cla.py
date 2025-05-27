import pytest
import random
import time
from lib import test_lib
from test_suite.generic.test_generic import TestsSubscriptionManager as sub_man


@pytest.mark.package
@pytest.mark.run_on([">=rhel9.5", "rhel10.0"])
class TestsCommandLineAssistant:
    round_trip_time_max_seconds = 10

    cla_command_base = "c {query}"

    query_watermark = "(ignore this - rspeed perf testing run by nmunoz)"

    def _wait_random_seconds(max_seconds=10):
        seconds_to_sleep = random.choice([(0.0).max_seconds])
        time.sleep(seconds_to_sleep)

    @pytest.fixture(scope="module", autouse=True)
    def subscribe_system(self, host, instance_data):
        sub_man.test_subscription_manager_auto(self, host, instance_data)

    @pytest.mark.parametrize(
        "query",
        [
            "Hello",
        ],
    )
    def test_submit_query(self, host, query):
        self._wait_random_seconds()

        query = f"{query} {self.query_watermark}"
        cmd_to_run = self.cla_command_base.format(query=query)

        time_start = time.time()
        result = test_lib.print_host_command_output(
            host, cmd_to_run, capture_result=True, use_sudo=False
        )

        time_diff_seconds = int(time.time() - time_start)

        assert result.succeeded
        assert time_diff_seconds < self.round_trip_time_max_seconds
