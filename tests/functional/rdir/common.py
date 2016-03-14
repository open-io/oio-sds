import random
import string


def generate_data(dictionary, n):
    return ''.join(random.choice(dictionary) for _ in range(n))


def generate_id(size):
    return generate_data(string.digits + 'ABCDEF', size)
