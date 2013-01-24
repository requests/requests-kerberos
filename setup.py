#!/usr/bin/env python
# coding: utf-8
import os
from setuptools import setup

import requests_kerberos

with open('requirements.txt') as requirements:
    requires = [line.strip() for line in requirements if line.strip()]

path = os.path.dirname(__file__)
desc_fd = os.path.join(path, 'README.rst')
hist_fd = os.path.join(path, 'HISTORY.rst')

long_desc = ''
short_desc = 'A Kerberos authentication handler for python-requests'

if os.path.isfile(desc_fd):
    long_desc = open(desc_fd).read()

if os.path.isfile(hist_fd):
    long_desc = '\n\n'.join([long_desc, open(hist_fd).read()])

setup(
    name='requests-kerberos',
    description=short_desc,
    long_description=long_desc,
    url='https://github.com/requests/requests-kerberos',
    packages=['requests_kerberos'],
    package_data={'': ['LICENSE', 'AUTHORS']},
    include_package_data=True,
    version=requests_kerberos.__version__,  # NOQA
    install_requires=requires,
)
