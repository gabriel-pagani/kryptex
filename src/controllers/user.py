from typing import Optional
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
    def create(cls, username: str, master_password: str) -> None:
        salt = urandom(32)
        master_password_hash = generate_hash(master_password)

        try:
            execute_query(
                query="INSERT INTO users (username, master_password_hash, salt) VALUES (?, ?, ?)",
                params=(username, master_password_hash, salt)
            )

        except Exception as e:
            print(f"exception-on-create: {e}")

    @classmethod
    def get(cls, username: str) -> Optional['User']:
        try:
            response = execute_query(
                "SELECT id, salt, username, master_password_hash FROM users WHERE username = ?",
                (username,)
            )
            
            if response != []:
                return cls(id=response[0][0], salt=response[0][1], username=response[0][2], master_password_hash=response[0][3])

        except Exception as e:
            print(f"exception-on-read: {e}")

    def delete(self) -> None:
        try:
            execute_query(
                query="DELETE FROM users WHERE username = ?",
                params=(self.username,)
            )

        except Exception as e:
            print(f"exception-on-delete: {e}")
