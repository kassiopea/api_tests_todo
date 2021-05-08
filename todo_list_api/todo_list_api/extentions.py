from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from redis import Redis

mongo = PyMongo()
redis = Redis()
jwt = JWTManager()
