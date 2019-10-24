from typing import TYPE_CHECKING, Tuple

from django.contrib.auth.hashers import check_password, make_password
from django.utils.crypto import get_random_string

if TYPE_CHECKING:
    from .models import APIKey


def concatenate(left, right):
    return "{}.{}".format(left, right)


def split(concatenated):
    left, _, right = concatenated.partition(".")
    return left, right


class KeyGenerator:
    def __init__(self, prefix_length=8, secret_key_length=32):
        self.prefix_length = prefix_length
        self.secret_key_length = secret_key_length

    def get_prefix(self):
        return get_random_string(self.prefix_length)

    def get_secret_key(self):
        return get_random_string(self.secret_key_length)

    def hash(self, value):
        return make_password(value)

    def generate(self):
        prefix = self.get_prefix()
        secret_key = self.get_secret_key()
        key = concatenate(prefix, secret_key)
        hashed_key = self.hash(key)
        return key, prefix, hashed_key

    def verify(self, key, hashed_key):
        return check_password(key, hashed_key)
