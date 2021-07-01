# Ветка dev_docker_tests
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Build Status](https://travis-ci.com/kassiopea/api_tests_todo.svg?branch=dev_docker_tests)](https://travis-ci.com/kassiopea/api_tests_todo)

<img alt="Python" src="https://img.shields.io/badge/python-%2314354C.svg?style=for-the-badge&logo=python&logoColor=white"/> <img alt="Flask" src="https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white"/> <img alt="MongoDB" src ="https://img.shields.io/badge/MongoDB-%234ea94b.svg?style=for-the-badge&logo=mongodb&logoColor=white"/> <img alt="TravisCI" src="https://img.shields.io/badge/travisci-%232B2F33.svg?style=for-the-badge&logo=travis&logoColor=white"/> <img alt="Docker" src="https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white"/>


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

### Остановка докера после прогона тестов
Удалить докер контейнеры: `sudo docker-compose down`

### Удаление докер образов
Удалить все образы: `sudo docker rmi $(sudo docker images -a -q)`