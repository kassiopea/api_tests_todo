import requests

from tests import BaseUrls, TodoUrls, BaseHeaders
from tests import Project
from tests import TodoErrors


class TestCheckInvalidCreateProject:

    def test_check_create_without_project_name(self, auth_token_new_user):
        url = BaseUrls.BASE_URL + TodoUrls.CREATE_PROJECT
        data = Project()
        headers = BaseHeaders.HEADERS
        headers['Authorization'] = auth_token_new_user
        requests_data = data.__dict__
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
        response_body = response.json()
        actual_response_error = response_body['errors'][0]['error']
        expected_response_error = TodoErrors.error_required_project_name_field
        assert response_body['data'] is None
        assert actual_response_error == expected_response_error, \
            f"Актуальный результат {actual_response_error} не соответствует ожидаемому: {expected_response_error}"

    def test_check_create_with_empty_project_name(self, auth_token_new_user):
        url = BaseUrls.BASE_URL + TodoUrls.CREATE_PROJECT
        data = Project()
        headers = BaseHeaders.HEADERS
        headers['Authorization'] = auth_token_new_user
        requests_data = data.__dict__
        response = requests.post(url=url, headers=headers, data=requests_data)
        assert response.status_code == 400
