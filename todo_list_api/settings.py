from datetime import timedelta
from os import environ, path
from dotenv import load_dotenv

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))

SECRET_KEY = environ.get('SECRET_KEY')
MONGO_URI = environ.get('DEV_DATABASE_URI')
REDIS_URI = environ.get('DEV_REDIS_URI')


ACCESS_EXPIRES = timedelta(minutes=120)
REFRESH_EXPIRES = timedelta(days=30)
JWT_ACCESS_TOKEN_EXPIRES = ACCESS_EXPIRES
JWT_REFRESH_TOKEN_EXPIRES = REFRESH_EXPIRES
JWT_BLACKLIST_ENABLED = environ.get('JWT_BLACKLIST_ENABLED')
JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']



