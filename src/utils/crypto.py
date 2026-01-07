import os
from argon2 import PasswordHasher

PEPPER = os.getenv("PEPPER", "")

# if PEPPER is "":
#     raise RuntimeError("CRITICAL ERROR: The environment variable 'PEPPER' is not defined.")

password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=32
)


def generate_hash(password: str) -> str:
    return password_hasher.hash(password + PEPPER)


def verify_hash(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password + PEPPER)
    except Exception as e:
        return False
