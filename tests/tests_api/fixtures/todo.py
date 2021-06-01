# import pytest
# import requests
#
# from tests.tests_api.constants import BaseUrls, TodoUrls
#
#
# class ApiTodo:
#     def __init__(self, base_url):
#         self.base_url = base_url
#
#     def post(self, path="", params=None, data=None, headers=None):
#         url = f"{self.base_url}{path}"
#         return requests.post(url=url, params=params, data=data, headers=headers)
#
#     def get(self, path='', params=None, headers=None):
#         url = f"{self.base_url}{path}"
#         return requests.get(url=url, params=params, headers=headers)
#
#
# @pytest.fixture
# def todo_list_api_base_url():
#     todo_url = f'{BaseUrls.BASE_URL}{TodoUrls.TODO_API}'
#     return ApiTodo(base_url=todo_url)
