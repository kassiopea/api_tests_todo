
class UserAuthErrors:
    error_required_field = 'Missing data for required field.'
    error_length_username = 'Длинна имени должна быть от 2 до 120 символов'
    error_length_password = 'Длинна пароля может содержать от 6 до 20 символов'
    error_invalid_username = 'Имя пользователя содержит недопустимые символы'
    error_invalid_email = 'Not a valid email address.'
    error_invalid_password = 'Пароль содержит недопустимые символы'
    error_user_already_exist = "Пользователь с таким имененм или почтой уже существует"
    error_required_login_fields = "Поля логин и пароль обязательны для заполнения"
    error_user_not_fount = "Такого пользователя не существует"
    error_without_auth_header = "Missing Authorization Header"
    error_invalid_token = "Signature verification failed"
    error_revoked_token = "Token has been revoked"
    error_required_change_pwd = "Текущий пароль и новый пароль являются обязательными полями."
    error_invalid_old_pwd = "Вы ввели неправильный пароль."
    error_old_pwd_equals_new_pwd = "Пароль не был изменен. Новый пароль совпадает с текущим."


class TodoErrors:
    error_required_project_name_field = "Имя проекта обзяатльное поле."
    error_required_field = "Не заполнено обязательное поле."
