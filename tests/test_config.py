
import pytest

from ec2userkeyd import config


def test_configfile_update(tmpdir):
    cfg = tmpdir.join('test_configfile.cfg')
    cfg.write("""
[general]
daemon_port = 909
iptables = /bin/false
credential_methods = UserRole, InstanceRole
per_user_credential_methods = joe:UserRole, InstanceRole, jane:UserRole
per_uid_credential_methods = 0-499:InstanceRole

[method_UserRole]
role_name_pattern = u-{username}

[method_InstanceRole]
fail_safe = true
""")
    
    config.update(str(cfg))
    assert config.general.daemon_port == 909
    assert config.general.iptables == '/bin/false'
    assert config.general.credential_methods == ['UserRole', 'InstanceRole']
    assert config.general.per_user_credential_methods == {
        'joe': 'UserRole, InstanceRole',
        'jane': 'UserRole'
    }
    assert config.general.per_uid_credential_methods == {
        '0-499': 'InstanceRole'
    }
    assert config.method_UserRole.role_name_pattern == 'u-{username}'
    assert config.method_InstanceRole.fail_safe == True


def test_configfile_bad_1(tmpdir):
    cfg = tmpdir.join('test_configfile.cfg')
    cfg.write("""
[method_DoesNotExist]
key_does_not_exist = True
""")

    with pytest.raises(Exception):
        config.update(str(cfg))


def test_configfile_bad_2(tmpdir):
    cfg = tmpdir.join('test_configfile.cfg')
    cfg.write("""
    [general]
key_does_not_exist = True
""")

    with pytest.raises(Exception):
        config.update(str(cfg))


def test_configfile_bad_3(tmpdir):
    cfg = tmpdir.join('test_configfile.cfg')
    cfg.write("""
[general]
daemon_port = True
""")

    with pytest.raises(ValueError):
        config.update(str(cfg))
