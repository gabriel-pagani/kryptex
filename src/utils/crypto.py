from dotenv import load_dotenv
import os
from argon2 import PasswordHasher

load_dotenv()

PEPPER = os.getenv("PEPPER", "")

if PEPPER == "":
    raise RuntimeError("CRITICAL ERROR: The environment variable 'PEPPER' is not defined.")

password_hasher = PasswordHasher(
    time_cost=12,
    memory_cost=262144,
    parallelism=12,
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
