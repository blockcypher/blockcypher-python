#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='blockcypher',
      version='0.1.4',
      description='Python BlockCypher Library',
      author='Michael Flaxman',
      author_email='mflaxman+blockcypher@gmail.com',
      url='https://github.com/blockcypher/blockcypher-python/',
      install_requires=[
          'requests==2.4.3',
          'python-dateutil==2.2',
          ],
      packages=['blockcypher'],
      include_package_data=True,
      package_data={"": ["LICENSE"]},
      )
