# Ветка dev_local
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Build Status](https://travis-ci.com/kassiopea/api_tests_todo.svg?branch=dev_local)](https://travis-ci.com/kassiopea/api_tests_todo)

<img alt="Python" src="https://img.shields.io/badge/python-%2314354C.svg?style=for-the-badge&logo=python&logoColor=white"/> <img alt="Flask" src="https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white"/> <img alt="TravisCI" src="https://img.shields.io/badge/travisci-%232B2F33.svg?style=for-the-badge&logo=travis&logoColor=white"/> 

## Перед запуском
Должны быть запущены базы данных:
- mongodb
- redis
Должны быть установлены:
- python 3.8
- pip
- virtualenv

Все приведенные команды на примере linux
- Установить git
- Клонировать репозиторий
- Перейти в директорию с проектом api_tests_todo_list
- Перейти в ветку dev_local: `git checkout dev_local`
- Активировать виртуальное окружение, например, командой `source test/bin/activate`
- Установить зависимости `pip install -r requirements.txt`
- Опционально: установить allure. Пример установки на linux bionic. В консоли:
    - `sudo curl -o allure-2.14.0.tgz -Ls https://github.com/allure-framework/allure2/releases/allure-2.14.0.tgz`
    -  `sudo tar -zxvf allure-2.14.0.tgz -C /opt/`
    - `sudo ln -s /opt/allure-2.6.0/bin/allure /usr/bin/allure`
    - `allure --version`
    
 *вместо allure-2.14.0.tgz подставить актуальную версию allure

### Запуск
- запускаем проект командой `flask run --host=0.0.0.0`
- запускаем скрипт для добавленя тестовых данных в Mongodb перед тестированием `mongo < mongo/mongo-init.js`
- запускаем тесты с выводом результатов в консоли `pytest -vs tests/tests_api/test_todo.py`
- запускаем тесты с allure (опционально) `pytest tests/tests_api/test_todo.py --alluredir=tests/tests_api/allure_reports`
- генерируем html allure после прогона тестов (опционально, если запускали тесты с allure) `allure serve tests/tests_api/allure_reports`

### После запуска
- останавливаем запущенное приложение `ctrl + C` в консоли, где запускали
