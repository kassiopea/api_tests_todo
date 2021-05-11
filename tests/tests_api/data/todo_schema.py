from pytest_schema import Or

schema_to_respond_to_post_request_to_add_todo = {
    "data": {
        "todo_id": str
    },
    "errors": Or(None, str),
    "status": int
}
