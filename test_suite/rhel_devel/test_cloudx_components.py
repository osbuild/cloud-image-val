import pytest
import importlib
from lib import console_lib


@pytest.mark.run_on(['all'])
def test_cloudx_components(host):
    cloudx_components_test_suites = {
        'awscli2': 'test_suite.package.test_awscli2',
        'opentelemetry-collector': 'test_suite.package.otel_package.test_otel'
    }

    failures_count = 0

    for component, module_name in cloudx_components_test_suites.items():
        try:
            module = importlib.import_module(module_name)
            test_classes = [cls for cls in vars(module).values() if isinstance(cls, type) and issubclass(cls, object)]

            for test_class in test_classes:
                console_lib.print_debug(f'TEST CLASS: {test_class.__name__}')

                if hasattr(test_class, "__pytest_mark__"):
                    # Run the test methods
                    for attr in dir(test_class):
                        if attr.startswith("test_"):
                            test_func = getattr(test_class, attr)
                            try:
                                test_func(host)
                                print(f'{component}::{attr} PASS')
                            except AssertionError as e:
                                print(f'{component}::{attr} FAIL - {e}')
                                failures_count += 1

        except ModuleNotFoundError:
            print(f'{component} SKIPPED (Module not found)')
            failures_count += 1

    assert failures_count == 0, 'One or more components failed. Please check the logs.'
