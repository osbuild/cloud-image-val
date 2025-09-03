import pytest

from schutzbot.get_civ_config import (
    detect_if_only_specific_methods_changed,
    CLOUD_TEST_FILES,
    GENERIC_TEST_FILE
)


def mock_get_method_changes_for_file(test_file):
    # Patch this function in tests
    return {
        CLOUD_TEST_FILES['aws']: {'test_aws_method1'},
        CLOUD_TEST_FILES['azure']: {'test_azure_method2'},
        CLOUD_TEST_FILES['gcp']: {'test_gcp_method3'},
        GENERIC_TEST_FILE: {'test_generic_method1', 'test_generic_method2'},
    }.get(test_file, set())


@pytest.mark.parametrize("files_changed,expected_mode,expected_clouds,expected_methods", [
    # Only one cloud file & one method changed
    ([CLOUD_TEST_FILES['aws']], 'cloud_methods', ['aws'], {'aws': {'test_aws_method1'}}),
    # Multiple cloud files & methods changed
    ([CLOUD_TEST_FILES['aws'], CLOUD_TEST_FILES['azure']], 'cloud_methods', ['aws', 'azure'], {
        'aws': {'test_aws_method1'},
        'azure': {'test_azure_method2'}
    }),
    # Only generic file and methods changed
    ([GENERIC_TEST_FILE], 'generic_methods', ['aws', 'azure', 'gcp'], {'generic': {'test_generic_method1', 'test_generic_method2'}}),
    # Non-test file changed
    (['schutzbot/get_civ_config.py'], 'full', None, None),
    # Test file with no method detection (should fallback to full)
    (['test_suite/cloud/test_unknown.py'], 'full', None, None),
    # Mixed test and non-test files (should fallback to full)
    ([CLOUD_TEST_FILES['aws'], 'schutzbot/get_civ_config.py'], 'full', None, None),
    # Invalid/unknown file path (should fallback to full)
    (['some/invalid/path.py'], 'full', None, None),
])
def test_detect_if_only_specific_methods_changed(monkeypatch, files_changed, expected_mode, expected_clouds, expected_methods):
    # Patch get_method_changes_for_file to simulate diffs
    monkeypatch.setattr(
        'schutzbot.get_civ_config.get_method_changes_for_file',
        mock_get_method_changes_for_file
    )
    result = detect_if_only_specific_methods_changed(files_changed)
    assert result['mode'] == expected_mode
    if expected_mode == 'cloud_methods':
        assert set(result['clouds']) == set(expected_clouds)
        for cloud in expected_clouds:
            assert result['methods'][cloud] == expected_methods[cloud]
    elif expected_mode == 'generic_methods':
        assert set(result['clouds']) == set(expected_clouds)
        assert result['methods']['generic'] == expected_methods['generic']
    elif expected_mode == 'full':
        assert 'clouds' not in result or result['clouds'] is None


def test_cloud_methods_multiple_changes(monkeypatch):
    """
    Test case to simulate and verify that the function correctly handles
    multiple changed methods within a single cloud test file.
    """
    # Create a test-specific mock function that returns multiple methods.
    def mock_multiple_changes_for_file(test_file):
        if test_file == CLOUD_TEST_FILES['aws']:
            return {'test_aws_method1', 'test_aws_method2', 'test_aws_method3'}
        return set()

    # Patch the main script's function with our temporary, test-specific mock.
    monkeypatch.setattr(
        'schutzbot.get_civ_config.get_method_changes_for_file',
        mock_multiple_changes_for_file
    )

    # Now, run the function with the changed file path.
    files_changed = [CLOUD_TEST_FILES['aws']]
    result = detect_if_only_specific_methods_changed(files_changed)

    # Assert that the result correctly contains all three changed methods.
    assert result['mode'] == 'cloud_methods'
    assert set(result['clouds']) == {'aws'}
    assert result['methods']['aws'] == {'test_aws_method1', 'test_aws_method2', 'test_aws_method3'}


def test_fallback_to_full_for_ambiguous(monkeypatch):
    # Simulate ambiguous change (no method detected)
    def mock_none(_):
        return set()
    monkeypatch.setattr(
        'schutzbot.get_civ_config.get_method_changes_for_file',
        mock_none
    )
    files_changed = [CLOUD_TEST_FILES['aws']]
    result = detect_if_only_specific_methods_changed(files_changed)
    assert result['mode'] == 'full'


def test_fallback_to_full_for_no_files():
    # Test that an empty list triggers 'full' mode fallback
    files_changed = []
    result = detect_if_only_specific_methods_changed(files_changed)
    assert result['mode'] == 'full'


def test_cloud_and_generic_methods(monkeypatch):
    # Simulate both cloud and generic methods changed
    def mock_both(test_file):
        if test_file == CLOUD_TEST_FILES['aws']:
            return {'test_aws_method1'}
        elif test_file == GENERIC_TEST_FILE:
            return {'test_generic_method2'}
        return set()
    monkeypatch.setattr(
        'schutzbot.get_civ_config.get_method_changes_for_file',
        mock_both
    )
    files_changed = [CLOUD_TEST_FILES['aws'], GENERIC_TEST_FILE]
    # Since both cloud and generic are touched, fallback to full for safety
    result = detect_if_only_specific_methods_changed(files_changed)
    assert result['mode'] == 'full'
