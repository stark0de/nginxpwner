#!/usr/bin/env python3
"""
Nginxpwner

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

"""
    Setup file for nginxpwner.
    Use setup.cfg to configure your project.

    This file was generated with PyScaffold 4.3.
    PyScaffold helps you to put up the scaffold of your new Python project.
    Learn more under: https://pyscaffold.org/
"""

from setuptools import setup, find_packages

setup(
	name='Nginxpwner',
	version ='0.1.0',
	url='https://github.com/stark0de/nginxpwner',
	author='stark0de',
	author_email='emal@replacethis.com',
	packages=find_packages(),
	include_package_data=True,
	package_data={"nginxpwner": ['data/*']},
	license='Apache 2.0',
	description='Nginxpwner is a simple tool to look for common Nginx misconfigurations and vulnerabilities.',
	long_description=open('README.md').read(),
	long_description_content_type='text/markdown',
	keywords=['Nginx' 'Audit Configuration' 'Nginx misconfigurations' 'Nginx vulnerabilities' ],
	scripts=['nginxpwner'],
	install_requires=[
	'requests_raw',
	'colorama',
    'bs4',
    'lxml',
	'requests'
	'packaging',
	'pyfiglet',
	'termcolor',
],

"""Install packages as defined in this file into the Python environment."""
from setuptools import setup, find_namespace_packages

# The version of this tool is based on the following steps:
# https://packaging.python.org/guides/single-sourcing-package-version/
VERSION = {}

with open("./src/Nginxpwner/__init__.py") as fp:
    # pylint: disable=W0122
    exec(fp.read(), VERSION)

setup(
    name="Nginxpwner",
    author="stark0de",
    author_email="hank@pythoncreate.com",
    url="https://github.com/stark0de/nginxpwner",
    description="Nginxpwner is a simple tool to look for common Nginx misconfigurations and vulnerabilities",
    version=VERSION.get("__version__", "0.0.0"),
    package_dir={"": "src"},
    packages=find_namespace_packages(where="src", exclude=["tests"]),
    include_package_data=True,
    package_data={"Nginxpwner": ["src/Nginxpwner/resources/*"]},
    install_requires=[
        "setuptools>=45.0",
        "requests_raw==0.2.1",
        "colorama==0.4.4",
        "requests==2.25.1",
        "packaging==20.9",
        "beautifulsoup4==4.9.3",
        "pyfiglet==0.8.post1",
        "termcolor==1.1.0",
        "lxml",
    ],
    entry_points={
        "console_scripts": [
            "Nginxpwner=Nginxpwner.__main__:main",
        ]
    },
    classifiers=[
        "Development Status :: 1 - Planning",
        "Programming Language :: Python :: 3.0",
        "Topic :: Utilities",
    ],
)
	classifiers=[
		'Programming Language :: Python :: 3.10',
		'Development Status :: 5 - Production/Stable',
		'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
		'Natural Language :: English',
		'Operating System :: POSIX :: Linux',
		'Environment :: Console',
	]
)