import allure
import pytest
from pytest_schema import schema
from .constants import TodoUrls, AuthUrls
from .data.description_valid import testdata
from .messages import ErrorMessages
from .data import todo_schema


# функция для удаления пользователя после тестов
def delete_user_after_test(auth_token, todo_list_api):
    url = f'{AuthUrls.AUTH}{AuthUrls.DELETE}'
    headers = {'Authorization': auth_token}
    response = todo_list_api.delete(path=url, headers=headers)
    with allure.step("Запрос отправлен. Проверяем, удалён ли пользователь."):
        assert response.status_code == 200, f'Пользователь не был удалён. Status code is {response.status_code}'


class TestCheckRequestWithoutToken:

    def test_check_status_code_after_adding_todo_without_token(self, todo_list_api, auth_token):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        data = {'description': 'test status code'}
        response = todo_list_api.post(path=url, data=data)
        expected_status_code = 401
        actual_status_code = response.status_code
        with allure.step("Запрос отправлен. Проверяем код ответа."):
            assert actual_status_code == expected_status_code, f'Код ответа {actual_status_code} ' \
                                                               f'не совпадает с ожидаемым {expected_status_code}'
        with allure.step("Проверяем, что ответ пришёл в json формате."):
            expected_headers = "application/json"
            actual_headers = response.headers['Content-Type']
            assert actual_headers == expected_headers
        with allure.step("Десериализируем ответ из json в словарь."):
            response_body = response.json()
        with allure.step(f'Проверим, что в ответе {response_body} нам пришёл оджидаемый текст ошибки.'):
            expected_msg = ErrorMessages.AUTH_NONE_TOKEN
            actual_msg = response_body['msg']
            assert expected_msg == actual_msg, f'Текст ошибки {actual_msg} ' \
                                               f'не совпадает с ожидаемым текстом {expected_msg}'

        with allure.step("Очищаем тестовые данные. Удаляем пользователя."):
            delete_user_after_test(auth_token, todo_list_api)


class TestCheckAddTodoWithOnlyRequiredFields:

    def test_check_status_code_adding_todo_with_only_required_fields(self, todo_list_api, auth_token):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field'}
        response = todo_list_api.post(path=url, headers=headers, data=data)
        assert response.status_code == 200

        delete_user_after_test(auth_token, todo_list_api)

    def test_check_response_json_after_adding_todo_with_only_required_fields(self, auth_token, todo_list_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field json'}
        response = todo_list_api.post(path=url, headers=headers, data=data)
        assert response.headers['Content-Type'] == "application/json"

        delete_user_after_test(auth_token, todo_list_api)

    def test_check_keys_in_response_after_adding_todo_with_only_required_fields(self, auth_token, todo_list_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field keys'}
        response = todo_list_api.post(path=url, headers=headers, data=data)
        response_body = response.json()
        response_keys = response_body.keys()
        assert response_keys == {'data', 'errors', 'status'}
        response_data = response_body['data']
        response_key = response_data.keys()
        assert response_key == {'todo_id'}

        delete_user_after_test(auth_token, todo_list_api)

    def test_check_id_in_response_after_adding_todo_with_only_required_fields(self, auth_token, todo_list_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field keys'}
        response = todo_list_api.post(path=url, headers=headers, data=data)
        response_body = response.json()
        response_data = response_body['data']
        response_key = response_data.keys()
        assert response_key == {'todo_id'}

        delete_user_after_test(auth_token, todo_list_api)

    def test_check_schema_todo_with_only_description(self, auth_token, todo_list_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field todo'}
        response = todo_list_api.post(path=url, headers=headers, data=data)
        # проверяем схему ответа
        response_body = response.json()
        assert schema(todo_schema.schema_to_respond_to_post_request_to_add_todo) == response_body

        delete_user_after_test(auth_token, todo_list_api)

    @pytest.mark.parametrize("todo", testdata)
    def test_check_adding_todo_with_valid_description(self, auth_token, todo_list_api, todo):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        # data = {'description': 'test required field todo'}
        data = vars(todo)
        response = todo_list_api.post(path=url, headers=headers, data=data)
        response_body = response.json()
        todo_id = response_body['data']['todo_id']

        # проверяем, что сущность сохранилась
        url_for_getting_todo_list = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        params = {'todo_id': todo_id}
        response_todo = todo_list_api.get(path=url_for_getting_todo_list, params=params, headers=headers)
        response_todo_body = response_todo.json()
        actual_id = response_todo_body['data'][0]['_id']
        assert actual_id == todo_id
        assert response_todo_body['data'][0]['description'] == data['description']

        delete_user_after_test(auth_token, todo_list_api)
