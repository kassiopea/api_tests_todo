from ..models.todo import Todo
from .generate_todo_data import generate_description_data

# проверка граничных значений и классов эквивалентности поля Описание
testdata = [
    Todo(description=generate_description_data(1)),
    Todo(description=generate_description_data(12)),
    Todo(description=generate_description_data(150)),
    Todo(description=generate_description_data(1000))
]
