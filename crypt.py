import hashlib
import random

__ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$" \
             "%^&*()!@_#%^&*()!@#$_%^&*()!@#'$%^&*()!@#\/$%^&*()!@#$%^&*()!@#$%^&*()"

static_salt = "7C9s#^@!(&v%IcD#"


def mk_salt(length=16):
    return ''.join([random.choice(__ALPHABET) for i in range(length)])


def hash_pass(password: str, dynamic_salt: str):
    return hashlib.md5(f"{static_salt}{password}{dynamic_salt}".encode('utf-8')).hexdigest()
