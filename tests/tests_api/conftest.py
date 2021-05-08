import importlib
import os
import json
import pytest
import requests

from .constants import BaseUrls, AuthUrls, BaseHeaders
from .data.generate_auth_data import generate_data
from .models.user import User


def add_options_console(parser):
    parser.addoption(
        "--target", action="store", default="target.json", help="выберете файл с настройками авторизации"
    )


@pytest.fixture(scope='session')
def create_test_admin_and_colors():
    url_for_auth_admin = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
    headers = BaseHeaders.HEADERS
    data_for_admin = User(username="admin_test_todo",
                          email="admin_test_todo@test.ru",
                          password="admin",
                          admin_key=os.environ.get('SECRET_KEY_FOR_ADMIN'))
    request_data_for_admin = vars(data_for_admin)
    response_for_admin = requests.post(url=url_for_auth_admin, headers=headers, data=request_data_for_admin)
    response_body_for_admin = response_for_admin.json()
    access_token = response_body_for_admin['access_token']



# @pytest.fixture(scope="class")
# def auth_token_new_user():
#     data = User(username=generate_data("username", 8),
#                 email=generate_data("email", 10),
#                 password=generate_data("password", 6))
#     request_data = data.__dict__
#
#     url = BaseUrls.BASE_URL + AuthUrls.AUTH + AuthUrls.REGISTER
#     headers = BaseHeaders.HEADERS
#     response = requests.post(url=url, headers=headers, data=request_data)
#     assert response.status_code == 200
#     response_body = response.json()
#     auth_token = 'Bearer ' + response_body['access_token']
#     return auth_token


# @pytest.fixture(scope='class')
# def get_header_with_token_new_users(request):
#     auth_credits = get_config(request)
#     url = BaseUrls.BASE_URL + AuthUrls.REGISTER
#     username = auth_credits['username']
#     email = auth_credits['email']
#     password = auth_credits['password']
#     data = User(username=username, email=email, password=password)
#     requests_data = data.__dict__
#     headers = BaseHeaders.HEADERS
#     response = requests.post(url, data=requests_data, headers=headers)
#     assert response.status_code == 200
#     response_body = response.json()
#     token = 'Bearer ' + response_body['access_token']
#     return token


def load_from_module(module):
    return importlib.import_module("data/data.{}".format(module)).test_data


def load_from_json(file):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data/{}.json".format(file))
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def pytest_generate_tests(metafunc):
    for fixture in metafunc.fixturenames:
        if fixture.startswith("json_"):
            module = load_from_json(fixture[5:])
            metafunc.parametrize(fixture, module, ids=[repr(id) for id in module])
        elif fixture.startswith("data_"):
            module = load_from_module(fixture[5:])
            metafunc.parametrize(fixture, module, ids=[repr(id) for id in module])


def get_config(request):
    config = os.path.join(os.path.dirname(os.path.abspath(__file__)), request.config.getoption("--target"))
    with open(config) as config_file:
        target = json.load(config_file)
    return target
