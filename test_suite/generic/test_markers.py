"""
The objective of this file is to facilitate testing of our markers.
Every time new markers are added, or the code in conftest.py is changed,
this testsuite should be run to make sure the markers work correctly.
"""
from datetime import datetime
import pytest


@pytest.mark.run_on(['all'])
def test_markers_all_no_wait():
    now = datetime.now()

    current_time = now.strftime("%H:%M:%S")
    print("Current Time =", current_time)


@pytest.mark.wait(120)
@pytest.mark.run_on(['all'])
def test_markers_all_do_wait():
    now = datetime.now()

    current_time = now.strftime("%H:%M:%S")
    print("Current Time =", current_time)


@pytest.mark.run_on(["rhel"])
def test_marker_only_rhel():
    print("rhel!")


@pytest.mark.run_on(["fedora"])
def test_marker_only_fedora():
    print("fedora!")


@pytest.mark.run_on(["centos"])
def test_marker_only_centos():
    print("centos!")


@pytest.mark.run_on(["rhel8.4"])
def test_marker_only_rhel_8_4():
    print("rhel8.4!")


@pytest.mark.run_on(["rhel8.4", "rhel8.7", "rhel8.8"])
def test_marker_only_rhel_8_4_8_7_8_8():
    print("rhel 8.4, 8.7, 8.8!")


@pytest.mark.run_on(["fedora36"])
def test_marker_only_fedora36():
    print("fedora36!")


@pytest.mark.run_on(["centos8"])
def test_marker_only_centos8():
    print("centos8!")


@pytest.mark.run_on([">rhel8.7"])
def test_marker_only_bigger_rhel8_7():
    print(">rhel8.7!")


@pytest.mark.run_on(["<rhel8.8"])
def test_marker_less_rhel8_8():
    print("<rhel8.8!")


@pytest.mark.run_on([">=rhel8.8", "rhel8.4"])
def test_marker_bigger_or_equal_rhel8_8_and_rhel8_4():
    print(">=rhel8.8 and rhel8.4!")


@pytest.mark.run_on([">rhel9.1", "fedora"])
def test_marker_bigger_rhel9_1_and_fedora():
    print(">rhel9.1 and fedora!")


@pytest.mark.run_on(["all"])
@pytest.mark.exclude_on(["<fedora37"])
def test_marker_all_exclude_less_fedora37():
    print("all_exclude_<fedora37!")


@pytest.mark.run_on(["rhel"])
@pytest.mark.exclude_on(["<rhel8.8"])
def test_marker_rhel8_exclude_less_rhel8_8():
    print("rhel8 exclude <rhel8.8!")


@pytest.mark.run_on(["all"])
@pytest.mark.jira_skip(["CLOUDX-425"])
def test_marker_all_skip_CLOUDX_425():
    print("all and skip CLOUDX_425!")


@pytest.mark.run_on(["rhel"])
@pytest.mark.jira_skip(["CLOUDX-190"])
def test_marker_rhel_not_skip_closed_CLOUDX_190():
    print("rhel and not skip CLOUDX-190!")
