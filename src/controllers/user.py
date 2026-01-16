from os import urandom
from typing import Optional, Tuple
from sqlite3 import IntegrityError
from database.connection import execute_query, get_connection
from utils.cryptor import generate_hash, verify_hash, derive_master_password, encrypt_data, decrypt_data


class User:
    def __init__(
        self, 
        id: int, 
        salt: bytes, 
        username: str,  
        master_password_hash: str,
        is_admin: bool,
    ):
        self.id = id
        self.salt = salt
        self.username = username
        self.master_password_hash = master_password_hash
        self.is_admin = is_admin

    @classmethod
    def create(cls, username: str, master_password: str, is_admin: bool = False) -> Tuple[Optional['User'], Optional[int], Optional[str]]:
        try:
            salt = urandom(32)
            master_password_hash = generate_hash(master_password)

            total_users = execute_query("SELECT COUNT(1) FROM users")
            is_admin = True if total_users[0][0] == 0 else is_admin
            
            response = execute_query(
                "INSERT INTO users (salt, username, master_password_hash, is_admin) VALUES (?, ?, ?, ?) RETURNING *",
                (salt, username, master_password_hash, is_admin)
            )

            if response != []:
                return cls(
                    id=response[0][0],
                    salt=response[0][1],
                    username=response[0][2],
                    master_password_hash=response[0][3],
                    is_admin=response[0][4],
                ), 1, "User created successfully!"
            raise Exception
            
        except IntegrityError as e:
            print(f"integrity-error: {e}")
            return None, 2, f"User already exists!"
        except Exception as e:
            print(f"exception-on-create: {e}")
            return None, 3, f"An unexpected error occurred! Please try creating your account again later."

    @classmethod
    def login(cls, username: str, master_password: str) -> Tuple[Optional['User'], Optional[bytes], Optional[int], Optional[str]]:
        try:
            response = execute_query(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            )

            if not response:
                return None, None, 2, "Invalid username and/or master password!"

            user = cls(
                id=response[0][0], 
                salt=response[0][1], 
                username=response[0][2], 
                master_password_hash=response[0][3],
                is_admin=response[0][4],
            )

            if verify_hash(user.master_password_hash, master_password):
                user_key = derive_master_password(master_password, user.salt)
                return user, user_key, 1, "Login successful!"
            else:
                return None, None, 2, "Invalid username and/or master password!"

        except Exception as e:
            print(f"exception-on-login: {e}")
            return None, None, 3, "An unexpected error occurred! Please try logging in again later."

    def update(
            self, 
            current_master_password: str, 
            new_username: Optional[str] = None, 
            new_master_password: Optional[str] = None, 
            is_admin: Optional[bool] = None
        ) -> bool:
        if not verify_hash(self.master_password_hash, current_master_password):
            return False

        if not new_username and not new_master_password and is_admin is None:
            return False

        # Usa conexão direta para garantir transação atômica (Rollback em caso de erro)
        conn = get_connection()
        try:
            cursor = conn.cursor()
            
            # Lógica de Rotação de Credenciais
            if new_master_password:
                # Deriva a chave ANTIGA para descriptografar os dados atuais
                old_key = derive_master_password(current_master_password, self.salt)
                
                # Gerar novos parâmetros de segurança
                new_salt = urandom(32)
                new_key = derive_master_password(new_master_password, new_salt)
                new_hash = generate_hash(new_master_password)
                
                # Busca todas as senhas do usuário
                cursor.execute(
                    "SELECT id, iv, encrypted_data FROM passwords WHERE user_id = ?", 
                    (self.id,)
                )
                passwords = cursor.fetchall()

                associated_data = f'user_id:{self.id};'.encode()

                for password_id, iv, encrypted_data_blob in passwords:
                    try:
                        # 1. Descriptografa para obter o dicionário (JSON)
                        data_dict = decrypt_data(old_key, iv, encrypted_data_blob, associated_data)
                        
                        # 2. Criptografa o dicionário novamente com a nova chave
                        new_iv, new_encrypted_data = encrypt_data(new_key, data_dict, associated_data)
                        
                        # Atualiza no banco
                        cursor.execute(
                            "UPDATE passwords SET iv = ?, encrypted_data = ? WHERE id = ?",
                            (new_iv, new_encrypted_data, password_id)
                        )
                    except Exception as e:
                        raise Exception(f"Failed to migrate password (ID={password_id}): {e}")

                # Atualiza os dados do usuário com a nova hash e salt
                cursor.execute(
                    "UPDATE users SET salt = ?, master_password_hash = ? WHERE id = ?",
                    (new_salt, new_hash, self.id)
                )
                
                # Atualiza o estado do objeto atual
                self.salt = new_salt
                self.master_password_hash = new_hash

            # Lógica de Atualização de Username
            if new_username:
                cursor.execute(
                    "UPDATE users SET username = ? WHERE id = ?", 
                    (new_username, self.id)
                )
                self.username = new_username

            if is_admin is not None:
                cursor.execute(
                    "UPDATE users SET is_admin = ? WHERE id = ?",
                    (is_admin, self.id)
                )
                self.is_admin = is_admin

            # Se chegamos até aqui sem erro, salva tudo
            conn.commit()
            return True

        except IntegrityError as e:
            print(f"integrity-error: {e}")
            conn.rollback()
            return False
        except Exception as e:
            print(f"exception-on-update: {e}")
            conn.rollback() # Desfaz todas as alterações se algo der errado
            return False
        finally:
            conn.close()

    def delete(self) -> bool:
        try:
            execute_query(
                "DELETE FROM users WHERE id = ?",
                (self.id,)
            )
            
            return True

        except IntegrityError as e:
            print(f"integrity-error: {e}")
            return False
        except Exception as e:
            print(f"exception-on-delete: {e}")
            return False
