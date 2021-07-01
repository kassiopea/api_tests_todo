from bson import ObjectId

from todo_list_api.extentions import mongo


def is_admin(current_id):
    users_collection = mongo.db.users
    admin_user = users_collection.find_one({'_id': ObjectId(current_id)})

    if admin_user['is_admin']:
        return True

    return False


def is_exist_elem(current_id, key, value):
    users_collection = mongo.db.users
    result = users_collection.find_one(
        {'_id': ObjectId(current_id), key: value}
    )
    if result:
        return True

    return False
