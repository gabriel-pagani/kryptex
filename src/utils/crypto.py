from dotenv import load_dotenv
import os
from argon2 import PasswordHasher, low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

load_dotenv()

PEPPER = os.getenv("PEPPER", "")

if PEPPER == "":
    raise RuntimeError("PEPPER is missing.")

password_hasher = PasswordHasher(
    time_cost=12,
    memory_cost=262144,
    parallelism=12,
    hash_len=32,
    salt_len=32
)


def generate_hash(master_password: str) -> str:
    return password_hasher.hash(master_password + PEPPER)


def verify_hash(master_password_hash: str, master_password: str) -> bool:
    try:
        return password_hasher.verify(master_password_hash, master_password + PEPPER)
    except Exception as e:
        return False


def derive_master_password(master_password: str, salt: bytes) -> bytes:
    return low_level.hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=12,
        memory_cost=262144,
        parallelism=12,
        hash_len=32,
        type=low_level.Type.ID
    )


def encrypt_password(derived_master_password: bytes, password: str) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(derived_master_password)
    iv = os.urandom(12)
    encrypted_password = aesgcm.encrypt(iv, password.encode(), None)
    return (iv, encrypted_password)


def decrypt_password(derived_master_password: bytes, iv: bytes, encrypted_password: bytes) -> str:
    try:
        aesgcm = AESGCM(derived_master_password)
        decrypted_password = aesgcm.decrypt(iv, encrypted_password, None).decode()
        return decrypted_password
    except InvalidTag:
        raise ValueError("Invalid key or Corrupted data")
