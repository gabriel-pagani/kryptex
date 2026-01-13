from typing import Optional, List
from datetime import datetime
from database.connection import execute_query
from utils.cryptor import encrypt_password


class Password:
    def __init__(
        self,
        id: int,
        user_id: int,
        type_id: Optional[int],
        service: str,
        login: Optional[str],
        iv: bytes,
        encrypted_password: bytes,
        url: Optional[str],
        notes: Optional[str],
        created_at: datetime,
        updated_at: Optional[datetime],
        deleted_at: Optional[datetime],
    ):
        self.id = id
        self.user_id = user_id
        self.type_id = type_id
        self.service = service
        self.login = login
        self.iv = iv
        self.encrypted_password = encrypted_password
        self.url = url
        self.notes = notes
        self.created_at = created_at
        self.updated_at = updated_at
        self.deleted_at = deleted_at

    @classmethod
    def create(
        cls,         
        user_id: int,
        user_key: bytes,
        service: str,
        password: str,
        type_id: Optional[int] = None,
        login: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional['Password']:
        try:
            associated_data = f'user_id:{user_id};'.encode()
            iv, encrypted_password = encrypt_password(user_key, password, associated_data)
            
            response = execute_query(
                "INSERT INTO passwords (user_id, type_id, service, login, iv, encrypted_password, url, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *",
                (user_id, type_id, service, login, iv, encrypted_password, url, notes)
            )

            if response != []:
                return cls(
                    id=response[0][0],
                    user_id=response[0][1],
                    type_id=response[0][2],
                    service=response[0][3],
                    login=response[0][4],
                    iv=response[0][5],
                    encrypted_password=response[0][6],
                    url=response[0][7],
                    notes=response[0][8],
                    created_at=response[0][9],
                    updated_at=response[0][10],
                    deleted_at=response[0][11],
                )
            return None
            
        except Exception as e:
            print(f"exception-on-create: {e}")
            return None

    @classmethod
    def get(cls, id: int) -> Optional['Password']:
        try:
            response = execute_query(
                "SELECT * FROM passwords WHERE id = ?",
                (id,)
            )

            if response != []:
                return cls(
                    id=response[0][0],
                    user_id=response[0][1],
                    type_id=response[0][2],
                    service=response[0][3],
                    login=response[0][4],
                    iv=response[0][5],
                    encrypted_password=response[0][6],
                    url=response[0][7],
                    notes=response[0][8],
                    created_at=response[0][9],
                    updated_at=response[0][10],
                    deleted_at=response[0][11],
                )
            return None

        except Exception as e:
            print(f"exception-on-get: {e}")
            return None

    @classmethod
    def get_all_by_user(cls, user_id: int) -> List['Password']:
        try:
            response = execute_query(
                "SELECT * FROM passwords WHERE user_id = ? ORDER BY service",
                (user_id,),
            )

            passwords = []
            if response:
                for row in response:
                    passwords.append(
                        cls(
                            id=row[0],
                            user_id=row[1],
                            type_id=row[2],
                            service=row[3],
                            login=row[4],
                            iv=row[5],
                            encrypted_password=row[6],
                            url=row[7],
                            notes=row[8],
                            created_at=row[9],
                            updated_at=row[10],
                            deleted_at=row[11],
                        )
                    )
            return passwords

        except Exception as e:
            print(f"exception-on-get-all: {e}")
            return []

    def update(
        self,
        user_key: bytes,
        type_id: Optional[int] = None,
        service: Optional[str] = None,
        login: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        deleted_at: Optional[datetime] = None,
    ) -> bool:
        try:
            if not self.id:
                return False

            if password:
                associated_data = f'user_id:{self.id};'.encode()
                iv, encrypted_password = encrypt_password(user_key, password, associated_data)

            fields = list()
            values = list()
            if type_id:
                fields.append("type_id = ?")
                values.append(type_id)
            if service:
                fields.append("service = ?")
                values.append(service)
            if login:
                fields.append("login = ?")
                values.append(login)
            if iv:
                fields.append("iv = ?")
                values.append(iv)
            if encrypted_password:
                fields.append("encrypted_password = ?")
                values.append(encrypted_password)
            if url:
                fields.append("url = ?")
                values.append(url)
            if notes:
                fields.append("notes = ?")
                values.append(notes)
            if deleted_at:
                fields.append("deleted_at = ?")
                values.append(deleted_at)
            
            if not fields:
                return False

            values.append(self.id)
            execute_query(
                f"UPDATE passwords SET {', '.join(fields)} WHERE id = ?", 
                tuple(values)
            )
            
            self.type_id = type_id if type_id else self.type_id
            self.service = service if service else self.service
            self.login = login if login else self.login
            self.iv = iv if iv else self.iv
            self.encrypted_password = encrypted_password if encrypted_password else self.encrypted_password
            self.url = url if url else self.url
            self.notes = notes if notes else self.notes
            self.deleted_at = deleted_at if deleted_at else self.deleted_at

            return True

        except Exception as e:
            print(f"exception-on-update: {e}")
            return False

    def delete(self) -> bool:
        try:
            if not self.id:
                return False
            
            execute_query(
                "DELETE FROM passwords WHERE id = ?",
                (self.id,)
            )
            
            return True

        except Exception as e:
            print(f"exception-on-delete: {e}")
            return False
