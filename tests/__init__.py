
import pytest

from ec2userkeyd import config


class MockConfig:
    def __init__(self, mocker):
        self.mocker = mocker

    def update(self, cfgs):
        for category in cfgs:
            for entry in cfgs[category]:
                self.mocker.patch.object(
                    getattr(config, category), entry, cfgs[category][entry])


@pytest.fixture
def mock_config(mocker):
    return MockConfig(mocker)


