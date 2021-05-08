from flask import Flask
from flask_cors import CORS

from todo_list_api.extentions import mongo, jwt, redis


def create_app(config_object='todo_list_api.settings'):
    app = Flask(__name__)

    app.config.from_object(config_object)

    redis.__init__(host='localhost', decode_responses=True)
    mongo.init_app(app)
    jwt.init_app(app)

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    from .users.routers import users
    from .auth.routers import auth
    from .colors.routers import colors
    from .todo.routers import todo

    app.register_blueprint(todo, url_prefix='/api/v1/todo_list/')
    app.register_blueprint(colors, url_prefix='/api/v1/colors/')
    app.register_blueprint(users, url_prefix='/api/v1/users/')
    app.register_blueprint(auth, url_prefix='/api/v1/auth/')

    # временно для проверки (потом удалить)
    @app.route('/')
    def index():
        return 'Hello from Docker!'

    return app
