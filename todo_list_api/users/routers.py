from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from todo_list_api.users.users import (
    get_current_user,
    add_marks,
    update_marks,
    get_marks,
    delete_mark,
    get_all_users
)

users = Blueprint('users', __name__)


@users.route('users', methods=['GET'])
@jwt_required
def get_users():
    current_id = get_jwt_identity()
    return get_all_users(current_id)


@users.route('profile', methods=['GET'])
@jwt_required
def user():
    current_id = get_jwt_identity()
    return get_current_user(current_id)


@users.route('user/marks', methods=['GET', 'POST'])
@jwt_required
def marks():
    if request.method == 'GET':
        current_id = get_jwt_identity()
        return get_marks(current_id)

    if request.method == 'POST':
        current_id = get_jwt_identity()
        data = request.form
        return add_marks(current_id, data)


@users.route('user/marks/<mark_id>', methods=['PUT', 'DELETE'])
@jwt_required
def mark(mark_id):
    if request.method == 'PUT':
        current_id = get_jwt_identity()
        data = request.form
        return update_marks(current_id, data, mark_id)

    if request.method == 'DELETE':
        current_id = get_jwt_identity()
        return delete_mark(current_id, mark_id)
