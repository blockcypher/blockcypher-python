import unittest

import os


FOO_ENV_VAR = os.getenv('FOO_ENV_VAR')


class TestTravis(unittest.TestCase):
    def test_env_var(self):
        if FOO_ENV_VAR:
            raise Exception('We have an env var')
        else:
            raise Exception('We do NOT have an env var')
