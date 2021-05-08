from datetime import datetime

from bson.objectid import ObjectId
from flask import jsonify
from todo_list_api.extentions import mongo
from todo_list_api.models.todo import Todo
from todo_list_api.todo.helper import parse_projects, make_response, parse_todo_json
from todo_list_api.todo.messages import ErrorMessages
from todo_list_api.todo.validates import validate_project, validate_todo


def get_ObjectId_list(list_items):
    result = []
    for item in list_items:
        result.append(ObjectId(item))
    return result


def add_project(user_id, request):
    projects_collection = mongo.db.projects
    raw_project_name = request.get('project_name', False)

    if not raw_project_name:
        error = [{'error': ErrorMessages.REQUIRED_FIELD}]
        response = make_response(status_code=400, data_errors=error)
        return response

    else:
        project_name = str(raw_project_name.strip())
        errors = validate_project(field='project_name', value=project_name)
        if errors:
            return make_response(status_code=400, data_errors=errors)

        existing_project = projects_collection.find_one({'project_name': project_name,
                                                         'author_id': ObjectId(user_id)})
        if existing_project:
            errors = [{'error': ErrorMessages.ENTRY_ALREADY_EXIST}]
            response = make_response(status_code=400, data_errors=errors)
            return response
        else:
            project = projects_collection.insert(
                {'project_name': str(raw_project_name), 'author_id': ObjectId(user_id)})
            data = {'project_id': str(project)}
            response = make_response(status_code=200, data=data)
            return response


# возможно нужен рефакторинг
def get_projects(user_id):
    todo_collection = mongo.db.projects
    data = []
    projects = todo_collection.find({'author_id': ObjectId(user_id)}, {'_id': 1, 'project_name': 1})
    result = parse_projects(projects)
    if result:
        data = result
    response = jsonify(data=data)
    return response


# возможно, нужен рефакторинг
def update_project(user_id, project_id, request):
    project_collection = mongo.db.projects
    project_name = request.get('project_name', False)
    errors = None
    if not project_name:
        errors = [{'message': 'укажите имя проекта'}]
    project_update = project_collection.update({'author_id': ObjectId(user_id), '_id': ObjectId(project_id)},
                                               {'$set': {'project_name': project_name}})

    response = jsonify(errors=errors, data=project_update)
    return response


# возможно, нужен рефакторинг
def delete_project(user_id, project_id):
    project_collection = mongo.db.projects
    project_del = project_collection.delete_one({'_id': ObjectId(project_id), 'author_id': ObjectId(user_id)})
    result = [{'acknowledged': project_del.acknowledged, 'deletedCount': project_del.deleted_count}]
    response = jsonify(data=result)
    return response


def add_todo(user_id, request):
    todo_collection = mongo.db.todo
    raw_description = request.get('description', None)
    raw_date = request.get('date', None)
    raw_project_id = request.get('project_id', None)
    list_id_marks = request.getlist('mark_id', None)
    author_id = str(user_id)

    if not raw_description:
        errors = [{'error': 'Описание задачи обзяатльное поле'}]
        response = make_response(status_code=400, data_errors=errors)
        return response
    else:
        description = str(raw_description.strip())
        project_id = None
        date = None

        if raw_date:
            date = str(raw_date.strip())

        data = Todo(description=description, date=date)
        request_data = vars(data)

        errors = validate_todo(request_data)
        if errors:
            return make_response(status_code=400, data_errors=errors)

        existing_todo = todo_collection.find_one({'description': description,
                                                  'author_id': ObjectId(user_id)})
        if existing_todo:
            errors.append({'description_error': 'Такое название задачи уже существует'})
            response = make_response(status_code=400, data_errors=errors)
            return response

        else:
            date_utc = None
            if raw_project_id:
                project_id = ObjectId(str(raw_project_id.strip()))

            if date:
                format_el = '%Y-%m-%dT%H:%M:%S.%fZ'
                date_utc = datetime.strptime(date, format_el)

            todo = todo_collection.insert({'author_id': ObjectId(author_id),
                                           'description': description,
                                           'date': date_utc, 'project_id': project_id, 'list_id_marks': list_id_marks})
            data = {'todo_id': str(todo)}
            response = make_response(status_code=200, data=data)
            return response


def get_todo_list(user_id, request):
    todo_collection = mongo.db.todo
    todo_id = request.args.get('todo_id', None)
    project_id = request.args.get('project_id', None)
    # date = request.args.get('date', None)
    mark_id = request.args.get('mark_id', None)

    filter_todo = {'author_id': ObjectId(user_id)}

    if todo_id is not None:
        filter_todo['_id'] = ObjectId(todo_id)

    if project_id is not None:
        filter_todo['project_id'] = ObjectId(project_id)

    if mark_id is not None:
        filter_todo['list_id_marks'] = str(mark_id)

    # добавить фильтр по дате (подумать о диапазоне дат)
    # if date is not None: filter['date'] = {'$lt': date}
    todo_list = todo_collection.find(filter_todo)

    result = parse_todo_json(todo_list)

    response = jsonify(data=result)
    return response
    # return Response(todo_list_api, mimetype="application/json", status=200)


def update_todo(user_id, todo_id, request):
    todo_collection = mongo.db.projects
    todo_description = request.get('description', None)
    # todo_date = request.get('date', None)
    # project_id = request.get('project_id', None)

    # errors = None
    # edited_todo = None
    if todo_description:
        todo_description = todo_description.strip()
        todo = Todo(description=todo_description)
        todo_for_validate = vars(todo)
        errors = validate_todo(todo_for_validate)

        if errors:
            return make_response(status_code=400, data_errors=errors)
        else:

            # if todo_date:
            #     format_el = '%Y-%m-%dT%H:%M:%S.%fZ'
            #     date_utc = datetime.strptime(todo_date, format_el)
            #     todo_date = date_utc

            edited_todo = todo_collection.update({'_id': ObjectId(todo_id), 'author_id': ObjectId(user_id)},
                                                 {'$set': {'description': todo_description}})

            # response = jsonify(errors=errors, data=edited_todo)
            response = make_response(status_code=200, data=edited_todo)
            return response

    else:
        errors = list({'error': ErrorMessages.REQUIRED_FIELD})
        response = make_response(status_code=400, data_errors=errors)
        return response


def delete_todo(user_id, todo_id):
    todo_collection = mongo.db.projects

    del_todo = todo_collection.update({'_id': ObjectId(todo_id), 'author_id': ObjectId(user_id)},
                                      {'$pull': {'todo_list_api': {'todo_id': ObjectId(todo_id)}}})

    return del_todo


def del_todo_date(user_id, project_id, todo_id):
    todo_collection = mongo.db.projects

    del_date = todo_collection.update({'_id': ObjectId(project_id), 'author_id': ObjectId(user_id),
                                       'todo_list_api.todo_id': ObjectId(todo_id)},
                                      {'$unset': {'todo_list_api.$.date': ""}})

    return del_date
