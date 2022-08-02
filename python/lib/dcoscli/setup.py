from codecs import open
from os import path

from setuptools import find_packages, setup

import dcoscli

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='dcoscli',
    version=dcoscli.version,
    description='DC/OS Command Line Interface',
    long_description=long_description,
    url='https://github.com/mesosphere/dcos-cli',
    author='Mesosphere, Inc.',
    author_email='help@dcos.io',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',
        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Software Development :: User Interfaces',
        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: Apache Software License',
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='mesos apache marathon mesosphere command datacenter',
    packages=find_packages(exclude=['tests', 'bin']),
    install_requires=[
        f'dcos=={dcoscli.version}',
        'docopt>=0.6, <1.0',
        'pkginfo==1.2.1',
        'toml>=0.9, <1.0',
        'virtualenv>=13.0, <16.0',
        'cryptography==2.3',
        'sseclient==0.0.19',
        'retrying==1.3.3',
    ],
    package_data={
        'dcoscli': ['data/*.json', 'data/help/*.txt'],
    },
    entry_points={
        'console_scripts': ['dcos=dcoscli.main:main'],
    },
)
