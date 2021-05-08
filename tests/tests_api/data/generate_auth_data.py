import random
import string


def generate_data(field: str, length: int) -> str:
    if length == 1:
        symbols = string.ascii_letters + string.digits
        random_one_symbol = ''.join(random.choices(symbols, k=1))
        return random_one_symbol
    if field == "username":
        first_symbol = string.ascii_letters + string.digits
        random_first_symbol = ''.join(random.choices(first_symbol, k=1))
        username_string = string.ascii_letters + string.digits + '-_.' * 4
        random_username_string = ''.join(random.choices(username_string, k=(length - 1)))
        result_username = random_first_symbol + random_username_string
        return result_username
    elif field == "password":
        passport_string = string.ascii_letters + string.digits + '-_:;!?()&#' * 4
        return ''.join(random.choices(passport_string, k=length))
    elif field == "email":
        first_part_email = string.ascii_letters + string.digits + '_-' * 4
        random_email_string = ''.join(random.choices(first_part_email, k=length))
        result_email = random_email_string + "@test.ru"
        return result_email


def generate_invalid_data(field: str, length: int) -> str:
    if field == "username":
        username_string = string.punctuation
        return ''.join(random.choices(username_string, k=length))
    elif field == "password":
        passport_string = string.punctuation
        return ''.join(random.choices(passport_string, k=length))
    elif field == "username_max_length":
        username_string = string.ascii_letters + string.digits + '-_.' * 10
        return ''.join(random.choices(username_string, k=length))
    elif field == "username_first_symbol":
        username_string = '-_.'
        random_first_symbol = ''.join(random.choices(username_string, k=1))
        if length == 1:
            return random_first_symbol

        username_string = string.ascii_letters + string.digits + '-_.' * 4
        random_username_string = ''.join(random.choices(username_string, k=length))
        result_username = random_first_symbol + random_username_string
        return result_username
