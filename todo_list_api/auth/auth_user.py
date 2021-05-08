from datetime import datetime
from os import environ

from flask import request, jsonify
from flask_jwt_extended import get_raw_jwt
from werkzeug.security import generate_password_hash, check_password_hash

from todo_list_api.auth.helper import get_token, authenticate, token_revoke, make_list_valid_errors, make_list_errors, \
    make_response_message
from todo_list_api.auth.validates import CreateRegistrationSchema, validate_new_password
from todo_list_api.extentions import mongo
from bson.objectid import ObjectId

from todo_list_api.settings import ACCESS_EXPIRES, REFRESH_EXPIRES


def register():
    create_registration_schema = CreateRegistrationSchema()
    users_collection = mongo.db.users

    username: str = request.form.get('username', None)
    email: str = request.form.get('email', None)
    password: str = request.form.get('password', None)
    admin_key: str = request.form.get('admin_key', None)
    current_admin_key = environ.get('SECRET_KEY_FOR_ADMIN')

    existing_user = users_collection.find_one({'username': username})
    existing_email = users_collection.find_one({'email': email})

    errors = create_registration_schema.validate(request.form)
    if errors:
        return make_list_valid_errors(400, str(errors))

    if existing_user is None and existing_email is None:
        hashed_password = generate_password_hash(password)
        is_active = True
        if admin_key == current_admin_key and admin_key is not None:
            is_admin = True
        elif admin_key is None:
            is_admin = False
        else:
            error_secret_key = {'error': 'Пользователь с ролью админ не создан'}
            return make_list_errors(status_code=400, data=error_secret_key)
        date_creation = datetime.utcnow()
        last_login = datetime.utcnow()

        _id = users_collection.insert(
            {
                'username': username, 'email': email, 'password': hashed_password,
                'is_active': is_active, 'is_admin': is_admin,
                'date_creation': date_creation, 'last_login': last_login
            }
        )

        response = get_token(str(_id))
        response.status_code = 200

        return response
    if existing_user is not None and existing_email is not None:
        error_user_already_exist = {'error': 'Пользователь с таким имененм или почтой уже существует'}
        return make_list_errors(status_code=400, data=error_user_already_exist)


def login():
    raw_username: str = request.form.get('username', None)
    raw_email: str = request.form.get('email', None)
    raw_password: str = request.form.get('password', None)

    if raw_password and raw_username:
        login_username = str(raw_username.strip())
        password = str(raw_password.strip())
        user = authenticate(login_username, password)
        return user
    elif raw_password and raw_email:
        login_email = str(raw_email.strip())
        password = str(raw_password.strip())
        user = authenticate(login_email, password)
        return user
    else:
        return make_list_errors(status_code=400, data={'login_error': 'Поля логин и пароль обязательны для заполнения'})


def logout():
    jti = get_raw_jwt()['jti']
    return token_revoke(jti, ACCESS_EXPIRES)


def logout2():
    jti = get_raw_jwt()['jti']
    return token_revoke((jti, REFRESH_EXPIRES))


def change_pwd(user_id, data):
    users_collection = mongo.db.users
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        error = {'error': 'Текущий пароль и новый пароль являются обязательными полями.'}
        status_code = 400
        response = make_response_message(status_code=status_code, error=error)
        return response

    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if check_password_hash(user.get("password"), old_password):
        if check_password_hash(user.get('password'), new_password):
            error = {'error': 'Пароль не был изменен. Новый пароль совпадает с текущим.'}
            status_code = 400
            response = make_response_message(status_code=status_code, error=error)
            return response
        else:
            error = validate_new_password(new_password)

            if error:
                error = str(error)
                response = make_list_errors(status_code=400, data=error)
                return response
            else:
                hashed_password = generate_password_hash(new_password)
                data = users_collection.update({'_id': ObjectId(user_id)},
                                               {'$set': {"password": hashed_password}})
                status_code = 200
                logout()
                response = make_response_message(status_code=status_code, data=data)
                return response

    elif not check_password_hash(user.get("password"), old_password):
        error = {'error': 'Вы ввели неправильный пароль.'}
        status_code = 400
        response = make_response_message(status_code=status_code, error=error)
        return response

    else:
        error = {'message': 'Пароль не был изменен. Иная причина.'}
        status_code = 400
        response = make_response_message(status_code=status_code, error=error, data=data)
        return response


def delete_user_account(user_id):
    users_collection = mongo.db.users
    projects_collection = mongo.db.projects
    todo_collection = mongo.db.todo

    deleted_todo_count = 0

    existing_todo = todo_collection.find({'author_id': ObjectId(user_id)})
    if existing_todo:
        deleted_todo = todo_collection.delete_many({'author_id': ObjectId(user_id)})
        deleted_todo_count = deleted_todo.deleted_count

    existing_projects = projects_collection.delete_many({'author_id': ObjectId(user_id)})
    if existing_projects:
        projects_collection.delete_many({'author_id': ObjectId(user_id)})

    logout()
    deleted_user = users_collection.delete_one({'_id': ObjectId(user_id)})
    deleted_user_count = deleted_user.deleted_count

    response_data = {'deleted_user_id': str(user_id), 'deleted_user_count': deleted_user_count,
                     'deleted_todo_count': deleted_todo_count}

    response = jsonify(data=response_data)
    response.status_code = 200

    return response
