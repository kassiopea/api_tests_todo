from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from todo_list_api.colors.colors import (
    get_marks_colors,
    add_colors,
    update_color,
    delete_color
)

colors = Blueprint('colors', __name__)


@colors.route('', methods=['GET', 'POST'])
@jwt_required
def color_items():
    if request.method == 'GET':
        return get_marks_colors()
    if request.method == 'POST':
        current_id = get_jwt_identity()
        data = request.form
        return add_colors(current_id, data)


@colors.route('<color_id>', methods=['PUT', 'DELETE'])
@jwt_required
def color_item(color_id):
    current_id = get_jwt_identity()
    if request.method == 'PUT':
        data = request.form
        return update_color(current_id, color_id, data)

    if request.method == 'DELETE':
        return delete_color(current_id, color_id)
