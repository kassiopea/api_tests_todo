from bson import ObjectId

from todo_list_api.extentions import mongo


def is_admin(current_id):
    users_collection = mongo.db.users
    admin_user = users_collection.find_one({'_id': ObjectId(current_id)})

    if admin_user['is_admin']:
        return True

    return False
