
import pytest

from ec2userkeyd.methods import base


class TestSource(base.BaseCredentialSource):
    def get(self, username, role):
        return {'Code': 'Success'}
    

def test_base_config(mocker):
    mocker.patch.object(base.config, 'method_TestSource', create=True)
    s = TestSource()
    assert isinstance(s.config, mocker.Mock)
