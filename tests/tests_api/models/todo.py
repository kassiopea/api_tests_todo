from datetime import datetime


class Todo:

    def __init__(self,
                 description: str = None,
                 todo_id: str = None,
                 author_id: str = None,
                 project_id: str = None,
                 date: datetime = None,
                 list_marks: list = None
                 ) -> None:
        self.description = description
        self.todo_id = todo_id
        self.author_id = author_id
        self.project_id = project_id
        self.date = date
        self.list_marks = list_marks

    def __repr__(self):
        return repr((self.description,
                     self.todo_id,
                     self.author_id,
                     self.project_id,
                     self.date,
                     self.list_marks))

    def __eq__(self, other):
        return self.description == other.description \
               and self.todo_id == other.todo_id \
               and self.author_id == other.author_id \
               and self.project_id == other.project_id \
               and self.date == other.date \
               and self.list_marks == other.list_marks
