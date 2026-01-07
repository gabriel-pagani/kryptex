from connection import get_connection


def create_tables():
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            salt BLOB NOT NULL,
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
            password_encrypted BLOB NOT NULL,
            url TEXT,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME,
            deleted_at DATETIME,

            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
            FOREIGN KEY (type_id) REFERENCES password_types(id) ON DELETE RESTRICT
        );
                       
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_id INTEGER,
            service TEXT NOT NULL,
            login TEXT,
            iv BLOB NOT NULL,
            password_encrypted BLOB NOT NULL,
            url TEXT,
            notes TEXT,
            changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE SET NULL
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
        BEFORE UPDATE OF password_encrypted ON passwords
        FOR EACH ROW
        BEGIN
            INSERT INTO password_history (
                password_id,
                service,
                login,
                iv,
                password_encrypted,
                url,
                notes,
                changed_at
            )
            VALUES (
                OLD.id,
                OLD.service,
                OLD.login,
                OLD.iv,
                OLD.password_encrypted,
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
                service,
                login,
                iv,
                password_encrypted,
                url,
                notes,
                changed_at
            )
            VALUES (
                OLD.id,
                OLD.service,
                OLD.login,
                OLD.iv,
                OLD.password_encrypted,
                OLD.url,
                OLD.notes,
                CURRENT_TIMESTAMP
            );
        END;
        """)


if __name__ == "__main__":
    create_tables()
