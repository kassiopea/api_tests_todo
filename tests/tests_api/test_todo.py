import allure
import pytest
from pytest_schema import schema
from .constants import TodoUrls
from .data.description_valid_date import testdata
from .data.messages import AuthErrors
from .data import todo_schema


@allure.description('Проверяем, что не будет создана '
                    'новая сущность todo без токена')
class TestCheckRequestWithoutToken:
    @allure.title('Проверить отправку запроса на создание todo без токена')
    @allure.description('Проверяем, что не будет создана'
                        ' новая сущность todo без токена')
    def test_check_status_code_after_adding_todo_without_token(
            self,
            todo_list_crud_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        data = {'description': 'test status code'}
        response = todo_list_crud_api.post(path=url, data=data)

        expected_status_code = 401
        actual_status_code = response.status_code

        with allure.step("Запрос отправлен. Проверяем код ответа."):
            assert actual_status_code == expected_status_code, \
                f'Код ответа {actual_status_code}' \
                f'не совпадает с ожидаемым {expected_status_code}'
        with allure.step("Проверяем, что ответ пришёл в json формате."):
            expected_headers = "application/json"
            actual_headers = response.headers['Content-Type']
            assert actual_headers == expected_headers

        with allure.step("Десериализируем ответ из json в словарь."):
            response_body = response.json()

        with allure.step('Проверим, что в ответе нам пришёл '
                         'оджидаемый текст ошибки.'):
            expected_msg = AuthErrors.AUTH_NONE_TOKEN
            actual_msg = response_body['msg']
            assert expected_msg == actual_msg, \
                f'Текст ошибки {actual_msg} ' \
                f'не совпадает с ожидаемым текстом {expected_msg}'


class TestCheckAddTodoWithRequiredField:
    @allure.title('Проверяем код ответа на запрос '
                  'с одним обязательным полем')
    @allure.description('Проверим, что код ответа 200 на запрос'
                        ' о создании todo только с полем Описание')
    def test_check_status_code_adding_todo(self,
                                           auth_token,
                                           todo_list_crud_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field'}
        response = todo_list_crud_api.post(path=url,
                                           headers=headers,
                                           data=data)

        with allure.step('Проверяем, что код ответа равен 200'):
            assert response.status_code == 200

    @allure.title('Проверяем content-type в ответе на запрос'
                  ' с одним обязательным полем')
    @allure.description('Проверяем, что тип ответа json на запрос '
                        'о создании todo только с полем Описание')
    def test_check_response_json_after_adding_todo(self,
                                                   auth_token,
                                                   todo_list_crud_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field json'}
        response = todo_list_crud_api.post(path=url,
                                           headers=headers,
                                           data=data)

        with allure.step('Проверяем, что ответ пришёл в json формате.'):
            assert response.headers['Content-Type'] == "application/json"

    @allure.title('Проверяем необходимые ключи в ответе '
                  'на запрос с одним обязательным полем')
    @allure.description('Проверяем ключи в ответе на запрос '
                        'о создании todo только с полем Описание')
    def test_check_keys_in_response_after_adding_todo(self, auth_token,
                                                      todo_list_crud_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field keys'}
        response = todo_list_crud_api.post(path=url,
                                           headers=headers,
                                           data=data)

        response_body = response.json()
        response_keys = response_body.keys()
        expected_keys = {'data', 'errors', 'status'}

        with allure.step(f'Проверяем, что в ответе '
                         f'есть ключи {expected_keys}'):
            assert response_keys == expected_keys

    @allure.title('Проверяем, что есть ключ с id todo '
                  'в ответе на запрос с одним обязательным полем')
    @allure.description('Проверяем наличие ключа todo_id'
                        ' в data в ответе на запрос '
                        'о создании todo только с полем Описание')
    def test_check_id_in_response_after_adding_todo(self,
                                                    auth_token,
                                                    todo_list_crud_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field keys'}
        response = todo_list_crud_api.post(path=url,
                                           headers=headers,
                                           data=data)

        response_body = response.json()
        response_data = response_body['data']
        response_key = response_data.keys()
        expected_key = {'todo_id'}

        with allure.step(f'Проверяем, что data содержит ключ {expected_key}'):
            assert response_key == expected_key

    @allure.title('Проверяем json схему ответа')
    @allure.description('Валидируем json схему ответа на запрос '
                        'о создании todo только с полем Описание')
    def test_check_schema_todo_with_only_description(self,
                                                     auth_token,
                                                     todo_list_crud_api):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = {'description': 'test required field todo'}
        response = todo_list_crud_api.post(path=url,
                                           headers=headers,
                                           data=data)

        # проверяем схему ответа
        response_body = response.json()
        with allure.step('Проверяем, что ответ '
                         'совпадает с ожидаемой json схемой'):
            assert schema(
                todo_schema.schema_to_respond_to_post_request_to_add_todo
            ) == response_body

    @allure.title('Проверяем, что todo создан c ожидаемым описанием')
    @allure.description('Проверяем граничные значения и '
                        'классы эквивалентности, '
                        'а также, что созданная сущность соответствует той, '
                        'что записана в бд. '
                        'Последнее проверим, запросив данные по id')
    @pytest.mark.parametrize("todo", testdata)
    def test_check_adding_todo_with_valid_description(self,
                                                      auth_token,
                                                      todo_list_crud_api,
                                                      todo):
        url = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
        headers = {'Authorization': auth_token}
        data = vars(todo)
        response = todo_list_crud_api.post(path=url,
                                           headers=headers,
                                           data=data)

        response_body = response.json()
        todo_id = response_body['data']['todo_id']

        with allure.step(f'Создали todo c описанием {todo.description}.'):
            assert response.status_code == 200, \
                f"Todo не была создана. Код ответа {response.status_code}"

        with allure.step('Отправляем запрос на получение информации '
                         'о только что созданной todo'):
            # проверяем, что сущность сохранилась
            url_for_getting_todo_list = f'{TodoUrls.TODO_API}{TodoUrls.TODO}'
            params = {'todo_id': todo_id}
            response_todo = todo_list_crud_api.get(
                path=url_for_getting_todo_list,
                params=params,
                headers=headers)

            response_todo_body = response_todo.json()
            actual_id = response_todo_body['data'][0]['_id']

            with allure.step('Проверяем, что в ответе '
                             'id todo соответствует ожидаемому'):
                assert actual_id == todo_id
            expected_description = data['description']
            actual_description = response_todo_body['data'][0]['description']

            with allure.step('Проверяем, что в ответе '
                             'описание соответствует ожидаемому'):
                assert actual_description == expected_description
