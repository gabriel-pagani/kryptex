import sqlite3
from pathlib import Path


DB_FILE = 'db.sqlite3'
DB_PATH = Path(__file__).resolve().parent / DB_FILE


def tables_exist(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users' LIMIT 1"
    ).fetchone()
    return row is not None


def create_tables(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            salt BLOB NOT NULL,
            username TEXT NOT NULL UNIQUE, 
            master_password_hash TEXT NOT NULL
        );
                       
        CREATE TABLE IF NOT EXISTS password_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
                       
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type_id INTEGER,
            service TEXT NOT NULL,
            login TEXT,
            iv BLOB NOT NULL,
            encrypted_password BLOB NOT NULL,
            url TEXT,
            notes TEXT,
            favorited BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME,
            deleted_at DATETIME,

            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
            FOREIGN KEY (type_id) REFERENCES password_types(id) ON DELETE RESTRICT
        );
                       
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_id INTEGER,
            user_id INTEGER NOT NULL,
            type_id INTEGER,
            service TEXT NOT NULL,
            login TEXT,
            iv BLOB NOT NULL,
            encrypted_password BLOB NOT NULL,
            url TEXT,
            notes TEXT,
            changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
            FOREIGN KEY (type_id) REFERENCES password_types(id) ON DELETE RESTRICT   
        );
                             
        CREATE INDEX IF NOT EXISTS idx_passwords_user ON passwords(user_id);
        CREATE INDEX IF NOT EXISTS idx_passwords_type ON passwords(type_id);
        CREATE INDEX IF NOT EXISTS idx_password_history_password ON password_history(password_id);
                             
        CREATE TRIGGER IF NOT EXISTS trg_passwords_updated
        AFTER UPDATE ON passwords
        FOR EACH ROW
        WHEN NEW.updated_at IS OLD.updated_at
        BEGIN
            UPDATE passwords
            SET updated_at = CURRENT_TIMESTAMP
            WHERE id = NEW.id;
        END;

        CREATE TRIGGER IF NOT EXISTS trg_passwords_history
        BEFORE UPDATE OF service, login, iv, encrypted_password, notes ON passwords
        FOR EACH ROW
        BEGIN
            INSERT INTO password_history (
                password_id,
                user_id,
                type_id,
                service,
                login,
                iv,
                encrypted_password,
                url,
                notes,
                changed_at
            )
            VALUES (
                OLD.id,
                OLD.user_id,
                OLD.type_id,
                OLD.service,
                OLD.login,
                OLD.iv,
                OLD.encrypted_password,
                OLD.url,
                OLD.notes,
                CURRENT_TIMESTAMP
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_passwords_history_on_delete
        BEFORE DELETE ON passwords
        FOR EACH ROW
        BEGIN
            INSERT INTO password_history (
                password_id,
                user_id,
                type_id,
                service,
                login,
                iv,
                encrypted_password,
                url,
                notes,
                changed_at
            )
            VALUES (
                OLD.id,
                OLD.user_id,
                OLD.type_id,
                OLD.service,
                OLD.login,
                OLD.iv,
                OLD.encrypted_password,
                OLD.url,
                OLD.notes,
                CURRENT_TIMESTAMP
            );
        END;
    """)


def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA foreign_keys = ON;")

    if not tables_exist(conn):
        create_tables(conn)

    return conn


def execute_query(query: str, params = None):
    with get_connection() as conn:
        cursor = conn.cursor()

        if params is not None:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        if cursor.description is not None:
            return cursor.fetchall()
