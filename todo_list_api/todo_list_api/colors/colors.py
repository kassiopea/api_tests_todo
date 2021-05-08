from bson import ObjectId
from flask import jsonify

from todo_list_api.colors.helper import get_marks_color
from todo_list_api.extentions import mongo
from todo_list_api.users.helper import is_admin


def get_marks_colors():
    marks_colors_collection = mongo.db.colors
    marks_colors = marks_colors_collection.find({})
    data = []
    for item in marks_colors:
        data.append({'_id': str(item['_id']), 'color': item['color'], 'hex_color': item['hex_color']})

    response = jsonify(data=data)
    return response


def add_colors(current_id, request):
    marks_colors_collection = mongo.db.colors
    errors = []
    code = 200
    messages = []
    data = []
    color = request['color']
    hex_color = request['hex_color']

    if is_admin(current_id):
        existing_hex_color = marks_colors_collection.find_one({'hex_color': hex_color})
        existing_color = marks_colors_collection.find_one({'color': hex_color})

        if existing_hex_color or existing_color:
            errors.append({'error': 'Цвет {}: {} уже существует в базе'.format(hex_color, color)})
        else:
            _id = marks_colors_collection.insert_one(
                {"color": color, "hex_color": hex_color}).inserted_id
            messages.append({'message': 'Цвет {}: {} добавлен в базу'.format(color, hex_color)})
            data.append({'_id': str(_id), 'color': color, 'hex_color': hex_color})

        if not messages:
            code = 400

    else:
        errors.append({'error': 'Добавлять цвета может только администратор.'})
        data = None
        messages = None
        code = 403

    response = jsonify(errors=errors, messages=messages, colors=data)
    response.status_code = code
    return response


def update_color(current_id, color_id, data):
    marks_colors_collection = mongo.db.colors
    color = data.get('color')
    hex_color = data.get('hex_color')
    errors = []
    messages = []
    new_color = []
    code = 200

    if is_admin(current_id):
        item_color = get_marks_color(color_id)
        if not item_color:
            errors.append({'error': 'Такого элемента не существует'})
            code = 400
        elif item_color['color'] == color and item_color['hex_color'] == hex_color:
            errors.append({'error': 'А ничего и не изменилось.'})
        else:
            marks_colors_collection.find_one_and_update({'_id': ObjectId(color_id)},
                                                        {'$set': {'color': color, 'hex_color': hex_color}})
            messages.append({'message': 'Изменения внесены'})
            new_color.append({'_id': color_id, 'color': color, 'hex_color': hex_color})

    else:
        errors.append({'error': 'Добавлять цвета может только администратор.'})
        code = 403

    response = jsonify(errors=errors, messages=messages, new_color=new_color)
    response.status_code = code

    return response


def delete_color(current_id, color_id):
    marks_colors_collection = mongo.db.colors
    errors = []
    messages = []
    deleted_color = []
    code = 200

    if is_admin(current_id):
        item_color = get_marks_color(color_id)
        if not item_color:
            errors.append({'error': 'Такого элемента не существует'})
            code = 400
        else:
            marks_colors_collection.delete_one({'_id': ObjectId(color_id)})
            messages.append({'message': 'Элемент успешно удален'})
            deleted_color.append({'_id': color_id, 'color': item_color['color'], 'hex_color': item_color['hex_color']})
    else:
        errors.append({'error': 'Добавлять цвета может только администратор.'})
        code = 403

    response = jsonify(errors=errors, messages=messages, deleted_color=deleted_color)
    response.status_code = code

    return response
