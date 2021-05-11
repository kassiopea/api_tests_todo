import pytest
import requests

from tests import BaseUrls, AuthUrls, BaseHeaders, UsersUrls
from tests import test_data
from tests import UserAuthErrors
from tests import UserAuthMessages
from tests import User
from tests import generate_data, generate_invalid_data


# функция для очистки пользователя после тестов
def clear_user_after_test(auth_token):
    url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.DELETE
    headers = {'Authorization': auth_token}
    response = requests.delete(url=url, headers=headers)
    assert response.status_code == 200
    assert response.headers['Content-Type'] == "application/json"
    response_body = response.json()
    assert response_body['data']['deleted_user_count'] == 1, 'Пользователь не был удалён'


@pytest.mark.negative
class TestCheckInvalidAuthorizationUser:

    def test_check_error_code_if_required_fields_are_missing(self):
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        data = User()
        headers = BaseHeaders.HEADERS
        requests_data = vars(data)
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"

    def test_check_error_messages_when_all_required_field_missing(self):
        expected_error_message = UserAuthErrors.error_required_field
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        data = User()
        headers = BaseHeaders.HEADERS
        requests_data = vars(data)
        response = requests.post(url=url, headers=headers, data=requests_data)
        response_body = response.json()
        response_errors = response_body['errors']
        errors_key = response_errors.keys()
        assert errors_key == {'password', 'username', 'email'}
        for key in response_errors:
            assert response_errors[key][0] == expected_error_message

    def test_check_message_error_if_no_required_field_username(self):
        expected_error_message = UserAuthErrors.error_required_field
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        data = User(email='without_username@test.ru', password='123456')
        headers = BaseHeaders.HEADERS
        requests_data = vars(data)
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'username' in response_errors
        actual_error_message = response_body['errors']['username'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_message_error_if_no_required_field_email(self):
        expected_error_message = UserAuthErrors.error_required_field
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        data = User(username='without_email', password='12345')
        headers = BaseHeaders.HEADERS
        requests_data = vars(data)
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'email' in response_errors
        actual_error_message = response_body['errors']['email'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_message_error_if_no_required_field_password(self):
        expected_error_message = UserAuthErrors.error_required_field
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        data = User(username='without_password', email='withoutPassword@test.ru')
        headers = BaseHeaders.HEADERS
        requests_data = vars(data)
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        actual_error_message = response_body['errors']['password'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_auth_error_with_empty_username(self):
        expected_error_message = UserAuthErrors.error_length_username
        data = User(username='', email='testEmpty@test.ru', password='123456')

        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        requests_data = vars(data)
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'username' in response_errors
        actual_error_message = response_body['errors']['username'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_auth_error_with_one_symbol_in_username(self):
        expected_error_message = UserAuthErrors.error_length_username
        username = generate_data(field='username', length=1)
        data = User(username=username, email='test_one_symbol@test.ru', password='123456')
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        requests_data = vars(data)
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'username' in response_errors
        actual_error_message = response_body['errors']['username'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_auth_error_with_over_max_121_symbols_in_username(self):
        expected_error_message = UserAuthErrors.error_length_username
        username = generate_data(field='username', length=121)
        data = User(username=username, email='test120username@test.ru', password='123456')
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)
        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        actual_error_message = response_body['errors']['username'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_auth_error_with_invalid_username(self):
        username = generate_invalid_data(field='username', length=10)
        expected_error_message = UserAuthErrors.error_invalid_username
        data = User(username=username, email='testInvalidUsername@test.ru', password='123456')
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)
        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'username' in response_errors
        actual_error_message = response_body['errors']['username'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_auth_error_start_with_invalid_symbol_in_username(self):
        username = generate_invalid_data(field='username_first_symbol', length=6)
        expected_error_message = UserAuthErrors.error_invalid_username
        data = User(username=username, email='testInvalidFirstSymbol@test.ru', password='123456')
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)
        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'username' in response_errors
        actual_error_message = response_body['errors']['username'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_auth_error_with_invalid_email(self):
        email = generate_invalid_data(field='username', length=6)
        expected_error_message = UserAuthErrors.error_invalid_email
        data = User(username='test_invalid_email', email=email, password='123456')
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)
        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'email' in response_errors
        actual_error_message = response_body['errors']['email'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

    def test_check_auth_error_with_invalid_password(self):
        password = generate_invalid_data(field='password', length=8)
        expected_error_message = UserAuthErrors.error_invalid_password
        data = User(username='test_invalid_password', email='testInvalidPassword@test.ru', password=password)
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)
        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_errors = response_body['errors']
        assert 'password' in response_errors
        actual_error_message = response_body['errors']['password'][0]
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)


@pytest.mark.positive
class TestValidAuthorizationUser:
    def test_check_auth_with_2_symbols_in_username_as_min_valid_length(self):
        username = generate_data(field='username', length=2)
        email = generate_data(field="email", length=8)
        password = generate_data(field="password", length=8)
        data = User(username=username, email=email, password=password)
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)

        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 200
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_body_key = response_body.keys()
        assert response_body_key == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # если тест был успешным, удалить тестового пользователя, который был создан для теста
        if response.status_code == 200 and 'access_token' in response_body_key:
            clear_user_after_test(auth_token)

    def test_check_auth_with_120_symbols_in_username_as_max_valid_length(self):
        username = generate_data(field='username', length=120)
        email = generate_data(field="email", length=7)
        password = generate_data(field="password", length=7)
        data = User(username=username, email=email, password=password)
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)

        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 200
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_body_key = response_body.keys()
        assert response_body_key == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # если тест был успешным, удалить тестового пользователя, который был создан для теста
        if response.status_code == 200 and 'access_token' in response_body_key:
            auth_token = 'Bearer ' + response_body['access_token']
            clear_user_after_test(auth_token)

    def test_check_auth_with_6_symbol_in_password_as_min_valid_length(self):
        username = generate_data(field='username', length=7)
        email = generate_data(field="email", length=8)
        password = generate_data(field="password", length=6)
        data = User(username=username, email=email, password=password)
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)

        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 200
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_body_key = response_body.keys()
        assert response_body_key == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # если тест был успешным, удалить тестового пользователя, который был создан для теста
        if response.status_code == 200 and 'access_token' in response_body_key:
            auth_token = 'Bearer ' + response_body['access_token']
            clear_user_after_test(auth_token)

    def test_check_auth_with_20_symbol_in_password_as_max_valid_length(self):
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=10)
        password = generate_data(field="password", length=20)
        data = User(username=username, email=email, password=password)
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(data)

        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 200
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_body_key = response_body.keys()
        assert response_body_key == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # если тест был успешным, удалить тестового пользователя, который был создан для теста
        if response.status_code == 200 and 'access_token' in response_body_key:
            auth_token = 'Bearer ' + response_body['access_token']
            clear_user_after_test(auth_token)

    @pytest.mark.parametrize("user_credentials", test_data, ids=[repr(x) for x in test_data])
    def test_check_auth_with_valid_data(self, user_credentials):
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers = BaseHeaders.HEADERS
        request_data = vars(user_credentials)
        response = requests.post(url=url, headers=headers, data=request_data)
        assert response.status_code == 200
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        response_body_key = response_body.keys()
        assert response_body_key == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == user_credentials.email, \
            f"Актуальный email: {actual_email} не совпадает с ожидаемым {user_credentials.email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == user_credentials.username, \
            f"Актуальный email: {actual_username} не совпадает с ожидаемым {user_credentials.username}"

        # если тест был успешным, удалить тестового пользователя, который был создан для теста
        if response.status_code == 200 and 'access_token' in response_body_key:
            auth_token = 'Bearer ' + response_body['access_token']
            clear_user_after_test(auth_token)


@pytest.mark.negative
class TestCheckInvalidLogin:

    def test_check_login_with_username_without_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг логин
        data_for_login = User(username=username)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        expected_error_message = UserAuthErrors.error_required_login_fields
        actual_error_message = response_body_login['errors']['login_error']
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_check_login_with_email_without_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг логин
        data_for_login = User(email=email)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        expected_error_message = UserAuthErrors.error_required_login_fields
        actual_error_message = response_body_login['errors']['login_error']
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_check_login_with_passport_without_login(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг логин
        data_for_login = User(password=password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        expected_error_message = UserAuthErrors.error_required_login_fields
        actual_error_message = response_body_login['errors']['login_error']
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_check_login_with_empty_username(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг логин
        data_for_login = User(username='', password=password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        expected_error_message = UserAuthErrors.error_required_login_fields
        actual_error_message = response_body_login['errors']['login_error']
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_check_login_with_empty_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг логин
        data_for_login = User(username=username, password="")
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        expected_error_message = UserAuthErrors.error_required_login_fields
        actual_error_message = response_body_login['errors']['login_error']
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_check_login_with_invalid_username(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг логин
        invalid_username = username + "1"
        data_for_login = User(username=invalid_username, password=password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        expected_error_message = UserAuthErrors.error_user_not_fount
        actual_error_message = response_body_login['errors']['error']
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_check_login_with_invalid_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг логин
        invalid_password = password + "1"
        data_for_login = User(username=username, password=invalid_password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        expected_error_message = UserAuthErrors.error_user_not_fount
        actual_error_message = response_body_login['errors']['error']
        assert actual_error_message == expected_error_message, "Текст ошибки '{}' не соответствует ожидаемой '{}'" \
            .format(actual_error_message, expected_error_message)

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)


@pytest.mark.positive
class TestCheckValidLogin:
    def test_check_login_valid_with_spaces_before_and_after_login(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}

        # основной шаг логин
        username_with_spaces = " " + username + "   "
        data_for_login = User(username=username_with_spaces, password=password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 200
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        response_login_keys = response_body_login.keys()
        assert response_login_keys == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body_login['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, \
            f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, \
            f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # удаляем нового пользователя после проверки логина
        if actual_email == email and actual_username == username:
            clear_user_after_test(auth_token)

    def test_check_login_valid_with_spaces_before_and_after_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}

        # основной шаг логин
        password_with_spaces = "   " + password + " "
        data_for_login = User(email=email, password=password_with_spaces)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 200
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        response_login_keys = response_body_login.keys()
        assert response_login_keys == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body_login['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, \
            f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, \
            f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # удаляем нового пользователя после проверки логина
        if actual_email == email and actual_username == username:
            clear_user_after_test(auth_token)

    def test_check_login_valid_with_valid_username_and_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}

        # основной шаг логин
        data_for_login = User(username=username, password=password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 200
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        response_login_keys = response_body_login.keys()
        assert response_login_keys == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body_login['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, \
            f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, \
            f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # удаляем нового пользователя после проверки логина
        if actual_email == email and actual_username == username:
            clear_user_after_test(auth_token)

    def test_check_login_valid_with_valid_email_and_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}

        # основной шаг логин
        data_for_login = User(email=email, password=password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 200
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        response_login_keys = response_body_login.keys()
        assert response_login_keys == {'access_token', 'refresh_token'}

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        auth_token = 'Bearer ' + response_body_login['access_token']
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': auth_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, \
            f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, \
            f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        # удаляем нового пользователя после проверки логина
        if actual_email == email and actual_username == username:
            clear_user_after_test(auth_token)


@pytest.mark.negative
class TestCheckInvalidLogout:
    def test_logout_without_token(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг разлогин
        url_for_logout = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGOUT
        response_for_logout = requests.delete(url=url_for_logout)
        assert response_for_logout.status_code == 401
        response_body = response_for_logout.json()
        assert response_for_logout.headers['Content-Type'] == "application/json"
        actual_error = response_body['msg']
        expected_error = UserAuthErrors.error_without_auth_header
        assert actual_error == expected_error

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_logout_with_invalid_token(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной шаг разлогин
        url_for_logout = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGOUT
        invalid_token = access_token + "1"
        headers_with_invalid_token = {'Authorization': invalid_token}
        response_for_logout = requests.delete(url=url_for_logout, headers=headers_with_invalid_token)
        assert response_for_logout.status_code == 422
        response_body = response_for_logout.json()
        assert response_for_logout.headers['Content-Type'] == "application/json"
        actual_error = response_body['msg']
        expected_error = UserAuthErrors.error_invalid_token
        assert actual_error == expected_error

        # удаляем нового пользователя после проверки логина
        clear_user_after_test(access_token)

    def test_logout_with_revoked_token(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # удаляем нового пользователя для получения протухшего токена
        clear_user_after_test(access_token)

        # основной шаг разлогин
        url_for_logout = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGOUT
        headers_with_invalid_token = {'Authorization': access_token}
        response_for_logout = requests.delete(url=url_for_logout, headers=headers_with_invalid_token)
        assert response_for_logout.status_code == 401
        response_body = response_for_logout.json()
        assert response_for_logout.headers['Content-Type'] == "application/json"
        actual_error = response_body['msg']
        expected_error = UserAuthErrors.error_revoked_token
        assert actual_error == expected_error


@pytest.mark.positive
class TestCheckValidLogout:
    def test_logout_with_valid_token(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий разлогина
        url_for_logout = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGOUT
        headers_with_token = {'Authorization': access_token}
        response_for_logout = requests.delete(url=url_for_logout, headers=headers_with_token)
        assert response_for_logout.status_code == 200
        response_body = response_for_logout.json()
        assert response_for_logout.headers['Content-Type'] == "application/json"
        actual_msg = response_body['data']
        expected_msg = UserAuthMessages.REVOKED_TOKEN
        assert actual_msg == expected_msg

        # если основной сценарий прошёл, удалить пользователя
        if response_for_logout.status_code == 200:
            clear_user_after_test(access_token)


@pytest.mark.negative
class TestCheckInvalidChangePassword:
    def test_check_change_pwd_without_required_old_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url_for_change_pwd = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.CHANGE_PASSWORD
        new_valid_password = generate_data(field="password", length=6)
        data_for_change_pwd = {'new_password': new_valid_password}
        headers_for_change_pwd = {'Authorization': access_token}
        print(data_for_change_pwd)
        request_for_change_password = requests.put(url=url_for_change_pwd,
                                                   headers=headers_for_change_pwd,
                                                   data=data_for_change_pwd)
        assert request_for_change_password.status_code == 400
        assert request_for_change_password.headers['Content-Type'] == "application/json"
        response_body = request_for_change_password.json()
        actual_error_message = response_body['errors']['error']
        expected_error_message = UserAuthErrors.error_required_change_pwd
        assert actual_error_message == expected_error_message, f"актуальный результат: {actual_error_message}" \
                                                               f"не совпадает с ожидаемым: {expected_error_message}"

        # удаляем тестового пользователя
        clear_user_after_test(access_token)

    def test_check_change_pwd_without_required_new_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url_for_change_pwd = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.CHANGE_PASSWORD
        data_for_change_pwd = {'old_password': password}
        headers_for_change_pwd = {'Authorization': access_token}
        request_for_change_password = requests.put(url=url_for_change_pwd,
                                                   headers=headers_for_change_pwd,
                                                   data=data_for_change_pwd)
        assert request_for_change_password.status_code == 400
        assert request_for_change_password.headers['Content-Type'] == "application/json"
        response_body = request_for_change_password.json()
        actual_error_message = response_body['errors']['error']
        expected_error_message = UserAuthErrors.error_required_change_pwd
        assert actual_error_message == expected_error_message, f"актуальный результат: {actual_error_message} " \
                                                               f"не совпадает с ожидаемым: {expected_error_message}"

        # удаляем тестового пользователя
        clear_user_after_test(access_token)

    def test_check_change_pwd_with_invalid_old_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url_for_change_pwd = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.CHANGE_PASSWORD
        invalid_password = password + "1"
        new_valid_password = generate_data(field="password", length=8)
        data_for_change_pwd = {'old_password': invalid_password, 'new_password': new_valid_password}
        headers_for_change_pwd = {'Authorization': access_token}
        request_for_change_password = requests.put(url=url_for_change_pwd,
                                                   headers=headers_for_change_pwd,
                                                   data=data_for_change_pwd)
        assert request_for_change_password.status_code == 400
        assert request_for_change_password.headers['Content-Type'] == "application/json"
        response_body = request_for_change_password.json()
        actual_error_message = response_body['errors']['error']
        expected_error_message = UserAuthErrors.error_invalid_old_pwd
        assert actual_error_message == expected_error_message, f"актуальный результат: {actual_error_message}" \
                                                               f"не совпадает с ожидаемым: {expected_error_message}"

        clear_user_after_test(access_token)

    def test_check_change_pwd_with_invalid_length_in_new_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url_for_change_pwd = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.CHANGE_PASSWORD
        new_invalid_password = generate_data(field="password", length=5)
        data_for_change_pwd = {'old_password': password, 'new_password': new_invalid_password}
        headers_for_change_pwd = {'Authorization': access_token}
        request_for_change_password = requests.put(url=url_for_change_pwd,
                                                   headers=headers_for_change_pwd,
                                                   data=data_for_change_pwd)
        assert request_for_change_password.status_code == 400
        assert request_for_change_password.headers['Content-Type'] == "application/json"
        response_body = request_for_change_password.json()
        actual_error_message = response_body['errors']['error']
        expected_error_message = UserAuthErrors.error_length_password
        assert actual_error_message == expected_error_message, f"актуальный результат: {actual_error_message}" \
                                                               f"не совпадает с ожидаемым: {expected_error_message}"

        clear_user_after_test(access_token)

    def test_check_change_pwd_with_invalid_symbol_in_new_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url_for_change_pwd = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.CHANGE_PASSWORD
        new_invalid_password = generate_data(field="password", length=6) + "<>"
        data_for_change_pwd = {'old_password': password, 'new_password': new_invalid_password}
        headers_for_change_pwd = {'Authorization': access_token}
        request_for_change_password = requests.put(url=url_for_change_pwd,
                                                   headers=headers_for_change_pwd,
                                                   data=data_for_change_pwd)
        assert request_for_change_password.status_code == 400
        assert request_for_change_password.headers['Content-Type'] == "application/json"
        response_body = request_for_change_password.json()
        actual_error_message = response_body['errors']['error']
        expected_error_message = UserAuthErrors.error_invalid_password
        assert actual_error_message == expected_error_message, f"актуальный результат: {actual_error_message}" \
                                                               f"не совпадает с ожидаемым: {expected_error_message}"

        clear_user_after_test(access_token)

    def test_check_change_pwd_with_the_same_old_and_new_passwords(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url_for_change_pwd = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.CHANGE_PASSWORD
        data_for_change_pwd = {'old_password': password, 'new_password': password}
        headers_for_change_pwd = {'Authorization': access_token}
        request_for_change_password = requests.put(url=url_for_change_pwd,
                                                   headers=headers_for_change_pwd,
                                                   data=data_for_change_pwd)
        assert request_for_change_password.status_code == 400
        assert request_for_change_password.headers['Content-Type'] == "application/json"
        response_body = request_for_change_password.json()
        actual_error_message = response_body['errors']['error']
        expected_error_message = UserAuthErrors.error_old_pwd_equals_new_pwd
        assert actual_error_message == expected_error_message, f"актуальный результат: {actual_error_message}" \
                                                               f"не совпадает с ожидаемым: {expected_error_message}"

        # удаляем тестового пользователя
        clear_user_after_test(access_token)


@pytest.mark.positive
class TestCheckValidChangePassword:
    def test_check_valid_change_password(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url_for_change_pwd = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.CHANGE_PASSWORD
        new_valid_password = generate_data(field="password", length=8)
        data_for_change_pwd = {'old_password': password, 'new_password': new_valid_password}
        headers_for_change_pwd = {'Authorization': access_token}
        request_for_change_password = requests.put(url=url_for_change_pwd,
                                                   headers=headers_for_change_pwd,
                                                   data=data_for_change_pwd)
        assert request_for_change_password.status_code == 200
        assert request_for_change_password.headers['Content-Type'] == "application/json"
        request_body = request_for_change_password.json()
        actual_modified = request_body['data']['nModified']
        assert actual_modified == 1, "Пароль не был изменен в базе данных"

        # проверка логина с новым паролем
        data_for_login = User(username=username, password=new_valid_password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        request_data_for_login = vars(data_for_login)
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 200
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        response_login_keys = response_body_login.keys()
        assert response_login_keys == {'access_token', 'refresh_token'}
        new_access_token = f'Bearer {response_body_login["access_token"]}'

        # проверим, валидный ли токен, запросом на получение данных о пользователе
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': new_access_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 200
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_email = response_for_get_credentials_body['email']
        assert actual_email == email, \
            f"Актуальный email: {actual_email} не совпадает с ожидаемым {email}"
        actual_username = response_for_get_credentials_body['username']
        assert actual_username == username, \
            f"Актуальный email: {actual_username} не совпадает с ожидаемым {username}"

        if response_for_login.status_code == 200:
            clear_user_after_test(new_access_token)


@pytest.mark.test
@pytest.mark.positive
class TestCheckDeleteUser:
    def test_check_delete_user(self):
        # подготовка к тесту (предусловие)
        username = generate_data(field='username', length=6)
        email = generate_data(field="email", length=6)
        password = generate_data(field="password", length=6)
        data_for_auth = User(username=username, email=email, password=password)
        url_for_auth = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
        headers_for_auth = BaseHeaders.HEADERS
        request_data_for_auth = vars(data_for_auth)
        response_for_auth = requests.post(url=url_for_auth, headers=headers_for_auth, data=request_data_for_auth)
        assert response_for_auth.status_code == 200
        assert response_for_auth.headers['Content-Type'] == "application/json"
        response_body_auth = response_for_auth.json()
        response_body_auth_token_key = response_body_auth.keys()
        assert response_body_auth_token_key == {'access_token', 'refresh_token'}
        access_token = f'Bearer {response_body_auth["access_token"]}'

        # основной сценарий
        url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.DELETE
        headers = {'Authorization': access_token}
        response = requests.delete(url=url, headers=headers)
        assert response.status_code == 200
        assert response.headers['Content-Type'] == "application/json"
        response_body = response.json()
        assert response_body['data']['deleted_user_count'] == 1, 'Пользователь не был удалён'

        # проверка запроса инфо о пользователе после удаления
        url_for_get_credentials = BaseUrls.BASE_URL + UsersUrls.USERS_API + UsersUrls.ABOUT_CURRENT_USER
        headers_for_current_user = {'Authorization': access_token}
        response_for_get_credentials = requests.get(url=url_for_get_credentials, headers=headers_for_current_user)
        assert response_for_get_credentials.status_code == 401
        assert response_for_get_credentials.headers['Content-Type'] == "application/json"
        response_for_get_credentials_body = response_for_get_credentials.json()
        actual_error_message_about_info = response_for_get_credentials_body['msg']
        expected_error_message_about_info = UserAuthErrors.error_revoked_token
        assert actual_error_message_about_info == expected_error_message_about_info

        # проверить авторизацию
        # data_for_login = User(username=username, password=password)
        url_for_login = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.LOGIN
        headers_for_login = BaseHeaders.HEADERS
        # request_data_for_login = vars(data_for_login)
        request_data_for_login = {'username': username, 'password': password}
        response_for_login = requests.post(url=url_for_login, headers=headers_for_login, data=request_data_for_login)
        assert response_for_login.status_code == 400
        assert response_for_login.headers['Content-Type'] == "application/json"
        response_body_login = response_for_login.json()
        actual_error_message_about_login = response_body_login['errors']['error']
        expected_error_message_about_login = UserAuthErrors.error_user_not_fount
        assert actual_error_message_about_login == expected_error_message_about_login

        if response_for_login.status_code == 400 == 200:
            clear_user_after_test(access_token)