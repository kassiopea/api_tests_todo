from bson import ObjectId

from todo_list_api.extentions import mongo


def get_marks_color(color_id):
    marks_colors_collection = mongo.db.colors
    return marks_colors_collection.find_one({'_id': ObjectId(color_id)})

