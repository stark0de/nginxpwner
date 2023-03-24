#!/usr/bin/env python3
"""
Nginxpwner!

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

from setuptools import setup, find_packages

setup(
	name='Nginxpwner',
	version='2.5.1-3',
	url='https://github.com/stark0de/nginxpwner',
	author='stark0de',
	author_email='emal@replacethis.com',
	packages=find_packages(),
	include_package_data=True,
	package_data={"nginxpwner": ['data/*']},
	license='GPL-V3',
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
	'packaging'.
	'pyfiglet',
	'termcolor',
    ],
	classifiers=[
		'Programming Language :: Python :: 3.10',
		'Development Status :: 5 - Production/Stable',
		'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
		'Natural Language :: English',
		'Operating System :: POSIX :: Linux',
		'Environment :: Console',
	]
)