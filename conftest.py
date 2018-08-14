import pytest


def pytest_addoption(parser):
    parser.addoption('--integration', action="store_true",
                     help="run integration tests")


def pytest_runtest_setup(item):
    """
    Only run tests marked with 'integration' when --integration is passed
    """
    run_integration = item.config.getoption("--integration")

    if 'integration' in item.keywords and not run_integration:
        pytest.skip("pass --integration option to pytest to run this test")
