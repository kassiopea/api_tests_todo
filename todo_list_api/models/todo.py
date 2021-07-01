from datetime import datetime


class Todo:
    def __init__(
            self,
            description: str = None,
            author_id: str = None,
            date: datetime.date or str = None
    ) -> None:
        self.description = description
        self.author_id = author_id
        self.date = date

    def __repr__(self):
        return repr((self.description, self.author_id, self.date))

    def __eq__(self, other):
        return self.description == other.description and \
               self.author_id == other.author_id and \
               self.date == other.date
