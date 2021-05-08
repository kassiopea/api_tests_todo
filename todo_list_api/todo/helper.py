import json
from flask import jsonify
from todo_list_api.extentions import mongo


def parse_objectId_to_string(list_items):
    result_list = []
    for item in list_items:
        result_list.append(str(item))
    return result_list


def parse_todo_list(response):
    res = []
    todo_item = {}
    list_todo_items = []
    for item in response:
        todo_item['project_id'] = str(item['_id'])
        todo_in_project = item['todo_list_api']

        for todo_i in todo_in_project:
            todo = {'_id': str(todo_i['_id']), 'description': todo_i['description']}

            if 'marks' in todo_i:
                todo['marks'] = todo_i['marks']

            if 'date' in todo_i:
                todo['date'] = todo_i['date']

            list_todo_items.append(todo)
        todo_item['todo_list_api'] = list_todo_items

        res.append(todo_item)

        todo_item = {}

    return res


def parse_projects(projects):
    result_projects = []
    for item in projects:
        project = {'_id': str(item['_id']), 'project_name': item['project_name']}
        result_projects.append(project)

    return result_projects


def create_project(user_id, project_name):
    projects = mongo.db.projects
    project = projects.insert({'project_name': project_name, 'author_id': user_id})

    return {'project_id': str(project)}


def make_response(status_code: int, data_errors: list = None, data: dict = None) -> json:
    response = jsonify({
        'status': status_code,
        'errors': data_errors,
        'data': data
    })
    response.status_code = status_code
    return response


# test parsing
def parse_todo_json(response):
    result_list = []
    for i in response:
        i_project_id = str(i['project_id'])
        project_id = None if i_project_id == "None" else i_project_id
        i_date = str(i['date'])
        date = None if i_date == "None" else i_date
        i_list_marks = None if i['list_id_marks'] == "None" else i['list_id_marks']

        item = {
            '_id': str(i['_id']),
            'author_id': str(i['author_id']),
            'description': str(i['description']),
            'date': date,
            'project_id': project_id,
            'list_id_marks': i_list_marks
        }
        result_list.append(item)

    return result_list
