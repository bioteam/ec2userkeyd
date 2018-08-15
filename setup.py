# tests require: ['pytest', 'pytest-mock', 'pytest-cov', 'responses']

from distutils.core import setup

requirements = ['flask', 'click', 'requests', 'boto3']

setup(
    name='ec2userkeyd',
    use_scm_version=True,
    packages=['ec2userkeyd'],
    entry_points={
        'console_scripts': ['ec2userkeyd=ec2userkeyd.cli:cli']
    },
    setup_requires=['setuptools_scm'],
    install_requires=requirements
)
