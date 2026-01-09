from os import urandom
from typing import Optional
from database.connection import execute_query
from utils.cryptor import generate_hash


class User:
    def __init__(
        self, 
        id: int, 
        salt: bytes, 
        username: str,  
        master_password_hash: str
    ):
        self.id = id
        self.salt = salt
        self.username = username
        self.master_password_hash = master_password_hash

    @classmethod
    def create(cls, username: str, master_password: str) -> Optional['User']:
        try:
            salt = urandom(32)
            master_password_hash = generate_hash(master_password)

            response = execute_query(
                "INSERT INTO users (salt, username, master_password_hash) VALUES (?, ?, ?) RETURNING *",
                (salt, username, master_password_hash)
            )

            if response != []:
                return cls(
                    id=response[0][0],
                    salt=response[0][1],
                    username=response[0][2],
                    master_password_hash=response[0][3]
                )
            return None
            
        except Exception as e:
            print(f"exception-on-create: {e}")
            return None

    @classmethod
    def get(cls, id: int) -> Optional['User']:
        try:
            response = execute_query(
                "SELECT * FROM users WHERE id = ?",
                (id,)
            )
            
            if response != []:
                return cls(
                    id=response[0][0], 
                    salt=response[0][1], 
                    username=response[0][2], 
                    master_password_hash=response[0][3]
                )
            return None

        except Exception as e:
            print(f"exception-on-get: {e}")
            return None

    def delete(self) -> bool:
        try:
            if not self.id:
                return False
            
            execute_query(
                "DELETE FROM users WHERE id = ?",
                (self.id,)
            )
            
            return True

        except Exception as e:
            print(f"exception-on-delete: {e}")
            return False
