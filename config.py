# not jet in use
import os

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
env = os.path.join(basedir, '.env')
if os.path.exists(env):
    load_dotenv(env)
else:
    print('Warning: .env file not found')


class Config(object):
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY',
                                '51f52814-0071-11e6-a247-000ec6c2372c')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)


class DevConfig(Config):
    DEBUG = True


class TestConfig(Config):
    TESTING = True


class ProdConfig(Config):
    pass
