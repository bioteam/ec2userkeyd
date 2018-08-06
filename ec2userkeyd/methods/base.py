
from ec2userkeyd import config


class BaseCredentialSource:
    def get(self, username, role):
        raise NotImplementedError()

    @property
    def config(self):
        classname = 'method_' + self.__class__.__name__
        return getattr(config, classname)
            
