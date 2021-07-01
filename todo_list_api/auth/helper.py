import json

from flask import jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jti
)
from datetime import datetime

from werkzeug.security import check_password_hash

from todo_list_api.extentions import mongo, redis, jwt
from todo_list_api.settings import ACCESS_EXPIRES, REFRESH_EXPIRES


@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    jti = decrypted_token['jti']
    entry = redis.get(jti)
    if entry is None:
        return True
    return entry == 'true'


def get_token(user_id):
    access_token = create_access_token(identity=user_id)
    refresh_token = create_refresh_token(identity=user_id)

    access_jti = get_jti(encoded_token=access_token)
    refresh_jti = get_jti(encoded_token=refresh_token)

    redis.set(access_jti, 'false', ACCESS_EXPIRES * 1.2)
    redis.set(refresh_jti, 'false', REFRESH_EXPIRES * 1.2)

    token = jsonify(access_token=access_token, refresh_token=refresh_token)
    return token


def authenticate(login, password):
    users_collection = mongo.db.users
    user = users_collection.find_one(
        {"$or": [{"username": login},
                 {"email": login}]}
    )

    if user and check_password_hash(user.get("password"), password):
        _id = str(user['_id'])
        last_login = datetime.utcnow()

        users_collection.update({'username': login},
                                {'$set': {"last_login": last_login}})

        token = get_token(_id)

        return token

    errors = {'error': 'Такого пользователя не существует'}
    response = make_list_errors(status_code=400, data=errors)
    return response


def refresh(user_id):
    access_token = create_access_token(identity=user_id)
    access_jti = get_jti(encoded_token=access_token)
    redis.set(access_jti, 'false', ACCESS_EXPIRES * 1.2)
    response = jsonify(access_token=access_token)
    response.status_code = 201
    return response


def token_revoke(jti, type_token):
    redis.set(jti, 'true', type_token * 1.2)
    data = 'Токен отозван'
    response = make_response_message(status_code=200, data=data)
    return response


def make_list_valid_errors(status_code, data=None):
    data_for_dict = data.replace("\'", "\"")
    result_data = json.loads(data_for_dict)
    response = jsonify({
                           'status': status_code,
                           'errors': result_data
                       } or {'error': 'Что-то пошло не так'})
    response.status_code = status_code
    # abort(response)
    return response


def make_list_errors(status_code: int, data: str or dict = None) -> json:
    if type(data) == str:
        data_for_dict = data.replace("\'", "\"")
        result_data = json.loads(data_for_dict)
    else:
        result_data = data
    response = jsonify({
                           'status': status_code,
                           'errors': result_data
                       } or {'error': 'Что-то пошло не так'})
    response.status_code = status_code
    return response


def make_response_message(status_code: int,
                          data: str or dict = None,
                          error: dict = None
                          ) -> json:
    response = jsonify({
        'status': status_code,
        'data': data,
        'errors': error
    })
    response.status_code = status_code
    return response
