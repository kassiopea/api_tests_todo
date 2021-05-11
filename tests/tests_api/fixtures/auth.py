import pytest
import requests


class ApiAuth:
    def __init__(self, base_url):
        self.base_url = base_url

    def post(self, base_url, path='', headers=None, params=None, data=None):
        url = f"{self.base_url}{path}"
        return requests.post(url=url, params=params, data=data, headers=headers)