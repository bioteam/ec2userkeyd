# tests require: ['pytest', 'pytest-mock', 'pytest-cov', 'responses']

from distutils.core import setup

requirements = ['flask', 'click', 'requests', 'boto3']

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='ec2userkeyd',
    use_scm_version=True,
    author="Karl Gutwin",
    author_email="karl@bioteam.net",
    description="EC2 user credential daemon",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=['ec2userkeyd'],
    entry_points={
        'console_scripts': ['ec2userkeyd=ec2userkeyd.cli:cli']
    },
    setup_requires=['setuptools_scm'],
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux"
    ],
)
