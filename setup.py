#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# read the contents of your README file
from os import path
from io import open
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(name='blockcypher',
      long_description=long_description,
      long_description_content_type='text/markdown',
      version='1.0.90',
      description='BlockCypher Python Library',
      author='Michael Flaxman',
      author_email='mflaxman+blockcypher@gmail.com',
      url='https://github.com/blockcypher/blockcypher-python/',
      install_requires=[
          'requests<3.0.0',
          'python-dateutil<3.0.0',
          'bitcoin==1.1.39',
          ],
      packages=['blockcypher'],
      include_package_data=True,
      package_data={"": ["LICENSE"]}
      )
