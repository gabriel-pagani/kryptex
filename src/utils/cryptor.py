from dotenv import load_dotenv
import os, secrets
from argon2 import PasswordHasher, low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

load_dotenv()

password_hasher = PasswordHasher(
    time_cost=12,
    memory_cost=262144,
    parallelism=12,
    hash_len=32,
    salt_len=32
)


def generate_hash(master_password: str) -> str:
    return password_hasher.hash(master_password)


def verify_hash(master_password_hash: str, master_password: str) -> bool:
    try:
        return password_hasher.verify(master_password_hash, master_password)
    except Exception as e:
        return False


def derive_master_password(master_password: str, salt: bytes) -> bytes:
    return low_level.hash_secret_raw(
        secret=(master_password).encode(),
        salt=salt,
        time_cost=12,
        memory_cost=262144,
        parallelism=12,
        hash_len=32,
        type=low_level.Type.ID
    )


def generate_password() -> str:
    characters = r"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&-_=~^,.<>;:()[]{}"
    password = ''.join(secrets.choice(characters) for _ in range(50))
    return password


def encrypt_password(derived_master_password: bytes, password: str, associated_data: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(derived_master_password)
    iv = os.urandom(12)
    encrypted_password = aesgcm.encrypt(iv, password.encode(), associated_data)
    return (iv, encrypted_password)


def decrypt_password(derived_master_password: bytes, iv: bytes, encrypted_password: bytes, associated_data: bytes) -> str:
    try:
        aesgcm = AESGCM(derived_master_password)
        decrypted_password = aesgcm.decrypt(iv, encrypted_password, associated_data).decode()
        return decrypted_password
    except InvalidTag:
        raise ValueError("Invalid key or Corrupted data.")
