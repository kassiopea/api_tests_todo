import re
from datetime import datetime


def validate_project(field: str, value: str) -> list:
    if field == 'project_name':
        if len(value) < 2 or len(value) > 120:
            errors = [{'error': 'Имя проекта должно содержать от 1 до 120 символов'}]
            return errors
        pattern_project_name = r'[0-9a-zA-zа-яА-ЯёЁ!,?"\-_\' ]+[ ]?$'
        if not re.match(pattern_project_name, value):
            errors = [{'error': 'Имя проекта содержит недопустимые символы'}]
            return errors


def validate_date(date_text, format_date):
    try:
        datetime.strptime(date_text, format_date)
        return True
    except ValueError:
        return False


def validate_todo(todo_item: dict) -> list:
    errors = []
    description = todo_item['description']
    date = todo_item['date']
    format_el = '%Y-%m-%dT%H:%M:%S.%fZ'
    if len(description) < 1 or len(description) > 1000:
        errors.append({'description_error': 'Описание задачи должно содержать от 1 до 1000 символов.'})

    if date:
        if not validate_date(date, format_el):
            errors.append({'date_error': 'Формат даты не совпадает с ГГГГ-ММ-ДД ЧЧ:ММ:СС'})

    return errors
