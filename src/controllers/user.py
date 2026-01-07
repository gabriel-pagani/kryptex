from os import urandom
from database.connection import execute_query
from utils.crypto import generate_hash


class User:
    def __init__(self, username: str, id: int = None, salt: bytes = None, master_password_hash: str = None):
        self.id = id
        self.salt = salt
        self.username = username
        self.master_password_hash = master_password_hash

    @classmethod
    def create(cls, username: str, master_password: str) -> bool:
        salt = urandom(32)
        master_password_hash = generate_hash(master_password)

        try:
            execute_query(
                query="INSERT INTO users (username, master_password_hash, salt) VALUES (?, ?, ?)",
                params=(username, master_password_hash, salt)
            )

            return True

        except Exception as e:
            print(f"exception-on-create: {e}")
            return False

    def delete(self) -> bool:
        try:
            execute_query(
                query="DELETE FROM users WHERE username = ?",
                params=(self.username,)
            )

            return True

        except Exception as e:
            print(f"exception-on-delete: {e}")
            return False
