# Здесь пока пусто

### Перед запуском
Должны быть запущены базы данных:
- mongodb
- redis

### Запуск проекта 
flask run --host=0.0.0.0`

### Запуск скрипта для изменения данных в Mongodb
`mongo < mongo/mongo-init.js`

### Запуск тестов с выводом результатов в консоли
`pytest -vs tests/tests_api/test_todo.py`

### Запуск тестов с allure
Для генерации тестов с allure локально, необходимо установить allure.
Пример установки на linux:
- скачиваем архив с актуальной версией с оф.сайта (в данном примере allure-commandline 2.14.0)
- в консоли распаковываем архив в директорию
`sudo tar -zxvf </path/to/folder/allure-commandline_2.14.0.tgz> -C /opt/`
- создаем символьную ссылку на исполняемый файл
`sudo ln -s /opt/allure-2.14.0/bin/allure /usr/bin/allure`
- проверяем версию allure
`allure --version`

Комманда запуска тестов с allure

`pytest tests/tests_api/test_todo.py --alluredir=tests/tests_api/allure_reports`

Генерация html allure после прогона тестов

`allure serve tests/tests_api/allure_reports`

