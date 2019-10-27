#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='blockcypher',
      version='1.0.77',
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
      package_data={"": ["LICENSE"]},
      )
