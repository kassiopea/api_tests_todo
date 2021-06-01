import random
import string


def generate_description_data(length: int) -> str:
    symbols = string.ascii_letters + string.digits
    description = ''.join(random.choices(symbols, k=1))
    if 1 < length <= 1000:
        symbols = string.ascii_letters + string.digits
        description = ''.join(random.choices(symbols, k=(length-1)))
    return description
