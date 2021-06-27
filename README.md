# Ветка dev_docker_tests
[![Build Status](https://travis-ci.com/kassiopea/api_tests_todo.svg?branch=dev_docker_tests)](https://travis-ci.com/kassiopea/api_tests_todo)

В этой ветке можно запустить проект с помощью докер контейнера вместе с базами данных

## Перед запуском
Все приведенные команды на примере linux
- Установить докер
- Установить git
- Клонировать репозиторий
- Перейти в директорию с проектом api_tests_todo_list
- Перейти в ветку dev_docker_tests: `git checkout dev_docker_tests`
- Опционально: установить allure. Пример установки на linux bionic. В консоли:
    - `sudo curl -o allure-2.14.0.tgz -Ls https://github.com/allure-framework/allure2/releases/allure-2.14.0.tgz`
    -  `sudo tar -zxvf allure-2.14.0.tgz -C /opt/`
    - `sudo ln -s /opt/allure-2.6.0/bin/allure /usr/bin/allure`
    - `allure --version`
    
 *вместо allure-2.14.0.tgz подставить актуальную версию allure

## Cборка и запуск проекта
В консоли команда: `sudo docker-compose up -d --build`

### Запуск тестов внутри контейнера
- Собрать и запустить проект
`sudo docker-compose exec -T todo_list_api pytest -vs`

### Запуск тестов вне докер образа

Перед запуском необходимо:
- установить virtualenv: `python -m venv venv`
- активировать переменное окружение `source venv/bin/activate`
- установить python (>=3.6)
- установить pytest: `pip install pytest`

Запуск тестов без allure:
 - `pytest -vs`

Запуск тестов с allure:

 - установить зависимости allure: `pip install allure-pytest`
 - запустить тесты с генерацией отчетов `pytest --alluredir=%allure_result_folder%`
 - сгенерировать отчет allure `allure serve %allure_result_folder%`

### Остановка докера после прогона тестов
Удалить докер контейнеры: `sudo docker-compose down`

### Удаление докер образов
Удалить все образы: `sudo docker rmi $(sudo docker images -a -q)`