import pytest

from main.cloud_image_validator import CloudImageValidator


class TestCloudImageValidator:
    test_resources_file = '/fake/test/resources_file.json'
    test_output_file = '/fake/test/output_file.xml'
    test_parallel = True
    test_debug = True

    @pytest.fixture
    def validator(self):
        return CloudImageValidator(self.test_resources_file,
                                   self.test_output_file,
                                   self.test_parallel,
                                   self.test_debug)

    def test_get_cloud_provider_from_resources_json(self, validator):
        assert False
    
    def test_main(self):
        assert False
    
    def test_initialize_infrastructure(self):
        assert False
    
    def test_deploy_infrastructure(self):
        assert False
    
    def test_run_tests_in_all_instances(self):
        assert False
    
    def test_report_test_results(self):
        assert False
    
    def test_destroy_infrastructure(self):
        assert False
