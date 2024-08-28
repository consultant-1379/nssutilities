import os
import glob

from setuptools import setup, find_packages


# This will generate the list of all our executable binary files in the required format
def get_entry_points():
    scripts = []
    scripts_paths = glob.glob("nssutils/bin/*.py")
    for sc in scripts_paths:
        file_path, _ = os.path.splitext(sc)
        module_path = file_path.replace('/', '.')
        module_name = module_path.split('.')[-1]
        if module_name not in ['__init__', '__main__']:
            scripts.append('{0}={1}:cli'.format(module_name, module_path))
    return scripts


# These are the folders we want to explicitely include in our installation because by default setup only includes
# python packages i.e folders containing '__init__.py'
PACKAGE_DATA = {'nssutils': ['etc/*.conf', 'etc/version_specific/*.conf', 'external_sources/*.*',
                             'external_sources/db/*', 'lib/resources/*.*', 'scripts/*.*',
                             'external_sources/scripts/*.*']}

setup(
    name='nssutils',
    author='NSS',
    packages=find_packages(),
    package_data=PACKAGE_DATA,
    include_package_data=False,
    zip_safe=True,
    platforms='any',

    # This will also install the dependency packages i.e, pycrypto, ecdsa will be installed while installing paramiko
    # These need to be installed in order to run our production tools
    install_requires=[
        "docopt",
        "enm_client_scripting",
        "enum34",
        "lxml",
        "paramiko",
        "redis",
        "requests",
        "Unipath",
        "ConcurrentLogHandler",
        "click",
        'unittest2',
        'responses',
        'mock',
        'epydoc',
        'fabric',
        'parameterizedtestcase',
        'pep8',
        'pylint',
        'fakeredis',
        'coverage',
        'autopep8',
        'nose-cprof',
        'nose-allure-plugin',
        'beautifulsoup4'
    ],
    entry_points={
        'console_scripts': get_entry_points(),
    },
    classifiers=[
        'Development Status :: 1 - Beta',
        'Environment :: Shell Scripting',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
