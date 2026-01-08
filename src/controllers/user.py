from typing import Optional
from os import urandom
from database.connection import execute_query
from utils.crypto import generate_hash, verify_hash


class User:
    def __init__(self, id: int, salt: bytes, username: str,  master_password_hash: str):
        self.id = id
        self.salt = salt
        self.username = username
        self.master_password_hash = master_password_hash

    @classmethod
    def create(cls, username: str, master_password: str) -> Optional['User']:
        salt = urandom(32)
        master_password_hash = generate_hash(master_password)

        try:
            execute_query(
                query="INSERT INTO users (username, master_password_hash, salt) VALUES (?, ?, ?)",
                params=(username, master_password_hash, salt)
            )

            return cls.get(username)

        except Exception as e:
            print(f"exception-on-create: {e}")
            return None

    @classmethod
    def get(cls, username: str) -> Optional['User']:
        try:
            response = execute_query(
                "SELECT id, salt, username, master_password_hash FROM users WHERE username = ?",
                (username,)
            )
            
            if response != []:
                return cls(id=response[0][0], salt=response[0][1], username=response[0][2], master_password_hash=response[0][3])
            return None

        except Exception as e:
            print(f"exception-on-read: {e}")
            return None

    def delete(self) -> bool:
        try:
            if not self.id:
                return False
            
            execute_query(
                query="DELETE FROM users WHERE id = ?",
                params=(self.id,)
            )

            return True

        except Exception as e:
            print(f"exception-on-delete: {e}")
            return False
        
    def check_master_password(self, master_password: str) -> bool:
        if not self.master_password_hash:
            return False
            
        return verify_hash(self.master_password_hash, master_password)
