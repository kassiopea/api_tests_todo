import os
import json

import allure
import pytest
import requests

from .constants import BaseUrls, AuthUrls, BaseHeaders
from .data.generate_auth_data import generate_data
from .models.user import User


# этот объект в теории можно вынести в отдельный helper или fixture
class ApiTodo:
    def __init__(self, base_url):
        self.base_url = base_url

    def post(self, path="", params=None, data=None, headers=None):
        url = f"{self.base_url}{path}"
        return requests.post(url=url, params=params,
                             data=data, headers=headers)

    def get(self, path='', params=None, headers=None):
        url = f"{self.base_url}{path}"
        return requests.get(url=url, params=params, headers=headers)

    def delete(self, path='', headers=None):
        url = f"{self.base_url}{path}"
        return requests.delete(url=url, headers=headers)


@allure.title('Передали базовый URL')
@pytest.fixture
def todo_list_crud_api():
    base_url = BaseUrls.BASE_URL
    return ApiTodo(base_url=base_url)


@allure.title('Авторизация пользователя')
@pytest.fixture
def auth_token(todo_list_crud_api, request):
    data_for_auth = User(username=generate_data("username", 8),
                         email=generate_data("email", 10),
                         password=generate_data("password", 6))
    data = vars(data_for_auth)

    auth_url = f'{AuthUrls.AUTH}{AuthUrls.REGISTER}'
    headers = BaseHeaders.HEADERS
    response = todo_list_crud_api.post(path=auth_url,
                                       headers=headers,
                                       data=data)
    with allure.step(f'Создали нового пользователя с именем: '
                     f'{data_for_auth.username}, '
                     f'почтой: {data_for_auth.email},'
                     f'паролем: {data_for_auth.password}'):
        assert response.status_code == 200
    response_body = response.json()
    auth_token = 'Bearer ' + response_body['access_token']

    def delete_user():
        url = f'{AuthUrls.AUTH}{AuthUrls.DELETE}'
        headers_for_delete_user = {'Authorization': auth_token}
        response_for_delete_user = todo_list_crud_api.delete(
            path=url, headers=headers_for_delete_user)
        with allure.step(f'Запрос отправлен. '
                         f'Проверяем, что пользователь '
                         f'{data_for_auth.username} удалён'):
            assert response_for_delete_user.status_code == 200, \
                f'Пользователь не был удалён. ' \
                f'Status code is {response.status_code}'

    request.addfinalizer(delete_user)
    return auth_token


def load_from_json(file):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "data/{}.json".format(file))
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def pytest_generate_tests(metafunc):
    for fixture in metafunc.fixturenames:
        if fixture.startswith("json_"):
            module = load_from_json(fixture[5:])
            metafunc.parametrize(fixture,
                                 module,
                                 ids=[repr(id) for id in module])
