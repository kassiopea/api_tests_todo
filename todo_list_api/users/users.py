from bson import json_util
from bson.objectid import ObjectId
from flask import jsonify, Response

from todo_list_api.extentions import mongo
from todo_list_api.users.helper import is_admin


def get_all_users(current_id):
    users_collections = mongo.db.users
    errors = []

    if is_admin(current_id):
        all_users = users_collections.find()
        data = json_util.dumps(all_users)
        return Response(data, mimetype='application/json')

    else:
        errors.append({'message': 'У вас нет доступа к этому ресурсу'})
        response = jsonify(errors=errors, data=None)
        response.status_code = 403
        return response


def get_current_user(current_id):
    users_collection = mongo.db.users
    user = users_collection.find_one({'_id': ObjectId(current_id)},
                                     {'username': 1, 'email': 1, '_id': 0})

    # return Response(user, mimetype="application/json", status=200)
    return user


def add_marks(current_id, request):
    users_collection = mongo.db.users
    result = []
    color_id = request.get('color_id', False)
    description = request.get('description', False)

    if not color_id:
        result.append({'error': 'укажите цвет марки'})
    elif not description:
        result.append({'error': 'укажите описание марки'})
    else:
        mark = {'mark_id': ObjectId(), 'color_id': color_id, 'description': description}
        mark_res = users_collection.update(
            {'_id': ObjectId(current_id), 'profile.marks.description': {'$ne': description}},
            {'$push': {'profile.marks': mark}})
        result.append(mark_res)

    response = jsonify(result)
    return response


def update_marks(current_id, request, mark_id):
    users_collection = mongo.db.users
    description = request['description']
    color_id = request['color_id']
    errors = None
    mark_result = users_collection.update({'_id': ObjectId(current_id), 'profile.marks.mark_id': ObjectId(mark_id)},
                                          {'$set': {'profile.marks.$.description': description,
                                                    'profile.marks.$.color_id': color_id}})
    if not mark_result:
        errors = [{'message': 'такого объекта не существует'}]

    response = jsonify(errors=errors, data=mark_result)
    return response


def get_marks(current_id):
    users_collection = mongo.db.users

    marks_list = users_collection.find({'_id': ObjectId(current_id)}, {'profile.marks': 1, '_id': 0})
    result = {'marks': []}

    for mark in marks_list[0]['profile']['marks']:
        result['marks'].append({'mark_id': str(mark['mark_id']), 'description': mark['description'],
                                'color_id': mark['color_id']})

    response = jsonify(data=result)
    return response


def delete_mark(current_id, mark_id):
    users_collection = mongo.db.users
    del_mark = users_collection.update({'_id': ObjectId(current_id)},
                                          {'$pull': {'profile.marks': {'mark_id': ObjectId(mark_id)}}})
    return del_mark
