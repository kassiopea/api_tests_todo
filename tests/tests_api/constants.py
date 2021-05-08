class BaseUrls:
    BASE_URL = "http://localhost:5000"


class AuthUrls:
    AUTH = '/api/v1/auth/'
    LOGIN = 'login'
    LOGOUT = 'logout'
    REGISTER = 'register'
    DELETE = 'delete'
    CHANGE_PASSWORD = 'change-password'


class BaseHeaders:
    HEADERS = {
        'Content-Type': "application/x-www-form-urlencoded",
    }


class TodoUrls:
    TODO_API = '/api/v1/todo_list/'
    CREATE_PROJECT = 'projects'
    CREATE_TODO = 'todo'


class UsersUrls:
    USERS_API = "/api/v1/users"
    ABOUT_CURRENT_USER = "/profile"

class Colors:
    COLORS_API = ""
