# Проект для api тестов

[![Build](https://img.shields.io/travis/com/kassiopea/api_tests_todo/main)](https://img.shields.io/travis/com/kassiopea/api_tests_todo/main)
[![Python 3.8](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/release/python-380/)

Проект был создан для резюме, чтобы показать пример api тестов

## О проекте
Тестовый проект написан с использованием:
- python 3.8
- flask
- mongodb
- redis

Приложение представляет собой rest api для создания todo.

Реализована регистрация и авторизация с помощью токена.

## Структура

- mongo - папка для скриптов для БД
    - mongo-init.js - скрипт для наполнения бд данными перед стартом тестов
- tests - папка со всеми тестами
    - data - папка для данных
        - description_valid.py - файл, с данными для параметризации. 
        Тестирование поля "Описание" (проверки граничных значений)
        - errors.py - файл, который содержит все тексты ошибок
        - generate_auth_data.py содержит функцию, генерирующую валидные и невалидные данные
        - messages.py содержит все тексты сообщений
        - 
        

## Методы API





