#!/usr/bin/env python
# coding: utf-8
import os
from setuptools import setup

version_file = 'requests_kerberos/__init__.py'
exec(compile(open(version_file).read(), version_file, 'exec'))

requires = ['kerberos', 'requests']

path = os.path.dirname(__file__)
desc_fd = os.path.join(path, 'README.rst')
hist_fd = os.path.join(path, 'HISTORY.rst')

long_desc = ''
short_desc = 'A Kerberos authentication handler for python-requests'

if os.path.isfile(desc_fd):
    long_desc = open(desc_fd).read()

if os.path.isfile(hist_fd):
    long_desc = '\n\n'.join(long_desc, open(hist_fd).read())

setup(
      name='requests-kerberos',
      description=short_desc,
      long_description=long_desc,
      url='https://github.com/requests/requests-kerberos',
      packages=['requests_kerberos'],
      package_data={'': ['LICENSE', 'AUTHORS']},
      include_package_data=True,
      version=__version__,  # NOQA
      install_requires=requires,
     )
