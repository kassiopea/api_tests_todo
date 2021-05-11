from ..data.generate_auth_data import generate_data
from ..models.user import User

test_data = [
    User(username=generate_data(field='username', length=10), email=generate_data(field='email', length=12),
         password=generate_data(field='password', length=8)),
    User(username=generate_data(field='username', length=14), email=generate_data(field='email', length=8),
         password=generate_data(field='password', length=13)),
    User(username=generate_data(field='username', length=52), email=generate_data(field='email', length=25),
         password=generate_data(field='password', length=18)),
]

