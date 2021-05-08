import re

from marshmallow import Schema, fields, validates, ValidationError


class CreateRegistrationSchema(Schema):
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)
    admin_key = fields.Str()

    @validates('username')
    def is_between_2_120_symbols_in_username(self, value):
        if len(value) < 2 or len(value) > 120:
            raise ValidationError("Длинна имени должна быть от 2 до 120 символов")

    @validates('username')
    def is_match_username_with_pattern(self, value):
        pattern_username = r'^[0-9a-zA-Z]+[0-9a-zA-Z-_.]+$'
        if not re.match(pattern_username, value):
            raise ValidationError("Имя пользователя содержит недопустимые символы")

    @validates('password')
    def is_between_6_20_symbols_in_password(self, value):
        if len(value) < 6 or len(value) > 20:
            raise ValidationError("Длинна пароля может содержать от 6 до 20 символов")

    @validates('password')
    def is_match_password_with_pattern(self, value):
        pattern_password = r'[0-9a-zA-Z-_:;!?()&#]+$'
        if not re.match(pattern_password, value):
            raise ValidationError("Пароль содержит недопустимые символы")


def validate_new_password(password: str):
    if len(password) < 6 or len(password) > 20:
        return {'error': "Длинна пароля может содержать от 6 до 20 символов"}

    pattern_password = r'[0-9a-zA-Z-_:;!?()&#]+$'
    if not re.match(pattern_password, password):
        return {'error': "Пароль содержит недопустимые символы"}
