class User:

    def __init__(self, username: str = None, email: str = None, password: str = None, admin_key: str = None) -> None:
        self.username = username
        self.email = email
        self.password = password
        self.admin_key = admin_key

    def __repr__(self):
        return repr((self.username, self.email, self.password, self.admin_key))

    def __eq__(self, other):
        return self.username == other.username and self.email == other.email and self.password == other.password
