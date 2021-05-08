from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from todo_list_api.todo.todo import add_todo, get_todo_list, add_project, get_projects, update_project, delete_project, \
    update_todo, delete_todo, del_todo_date

todo = Blueprint('todo', __name__)


@todo.route('projects', methods=['POST', 'GET'])
@jwt_required
def todo_projects():
    if request.method == 'POST':
        user_id = get_jwt_identity()
        data = request.form
        return add_project(user_id, data)
    if request.method == 'GET':
        user_id = get_jwt_identity()
        return get_projects(user_id)


@todo.route('projects/<project_id>', methods=['PUT', 'DELETE'])
@jwt_required
def todo_project(project_id):
    user_id = get_jwt_identity()

    if request.method == 'PUT':
        data = request.form
        return update_project(user_id, project_id, data)

    if request.method == 'DELETE':
        return delete_project(user_id, project_id)


@todo.route('todo', methods=['POST', 'GET'])
@jwt_required
def todo_list():
    if request.method == 'POST':
        user_id = get_jwt_identity()
        data = request.form
        return add_todo(user_id, data)
    if request.method == 'GET':
        user_id = get_jwt_identity()
        return get_todo_list(user_id, request)


# without crud marks in todo and del date
# переписать, есть варианты, когда нет id проекта, потому что туду вне проектов
@todo.route('todo/<todo_id>', methods=['PUT', 'DELETE'])
@jwt_required
def todo_edit_or_delete(todo_id):
    user_id = get_jwt_identity()
    if request.method == 'PUT':
        data = request.form
        return update_todo(user_id, todo_id, data)

    if request.method == 'DELETE':
        return delete_todo(user_id, todo_id)


# переписать, есть варианты, когда нет id проекта, потому что туду вне проектов
@todo.route('todo/<project_id>/<todo_id>/date', methods=['DELETE'])
@jwt_required
def delete_todo_date(project_id, todo_id):
    if request.method == 'DELETE':
        user_id = get_jwt_identity()
        return del_todo_date(user_id, project_id, todo_id)

