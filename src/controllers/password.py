from typing import Optional
from datetime import datetime
from database.connection import execute_query


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
