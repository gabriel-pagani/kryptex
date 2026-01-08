from dotenv import load_dotenv
import os
from argon2 import PasswordHasher, low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()

PEPPER = os.getenv("PEPPER", "")

if PEPPER == "":
    raise RuntimeError("error-on-crypto: PEPPER is missing.")

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


def encrypt_password(master_password: str, salt: bytes, password: str) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(derive_master_password(master_password, salt))
    iv = os.urandom(12)
    password_encrypted = aesgcm.encrypt(iv, password.encode(), None)
    return (iv, password_encrypted)


def decrypt_password(master_password: str, salt: bytes, iv: bytes, password_encrypted: bytes) -> str:
    try:
        aesgcm = AESGCM(derive_master_password(master_password, salt))
        password_decrypted = aesgcm.decrypt(iv, password_encrypted, None).decode()
        return password_decrypted
    except Exception as e:
        return ""
