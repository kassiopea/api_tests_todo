from flask import Blueprint, request
from flask_jwt_extended import (
    jwt_refresh_token_required, get_jwt_identity, jwt_required
)

from todo_list_api.auth import auth_user
from todo_list_api.auth.auth_user import logout, logout2, change_pwd, delete_user_account
from todo_list_api.auth.helper import refresh

auth = Blueprint('auth', __name__)


@auth.route('register', methods=['POST'])
def sing_up():
    return auth_user.register()


@auth.route('login', methods=['POST'])
def login():
    return auth_user.login()


@auth.route('refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh_token():
    current_id = get_jwt_identity()
    return refresh(current_id)


@auth.route('logout', methods=['DELETE'])
@jwt_required
def access_revoke():
    return logout()


@auth.route('refresh-revoke', methods=['DELETE'])
@jwt_refresh_token_required
def refresh_revoke():
    return logout2()


@auth.route('change-password', methods=['PUT'])
@jwt_required
def change_the_password():
    current_id = get_jwt_identity()
    data = request.form
    return change_pwd(current_id, data)


@auth.route('delete', methods=['DELETE'])
@jwt_required
def delete_account():
    if request.method == 'DELETE':
        current_id = get_jwt_identity()
        return delete_user_account(current_id)
