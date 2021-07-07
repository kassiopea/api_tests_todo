import json

from flask import jsonify


def parse_projects(projects):
    result_projects = []
    for item in projects:
        project = {'_id': str(item['_id']),
                   'project_name': item['project_name']}
        result_projects.append(project)

    return result_projects


def make_response(status_code: int,
                  data_errors: list = None,
                  data: dict = None
                  ) -> json:
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

        if i['list_id_marks'] == "None":
            i_list_marks = None
        else:
            i_list_marks = i['list_id_marks']

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
