from cryptography.fernet import Fernet
from django.conf import settings

def get_cipher():
    return Fernet(settings.ENCRYPTION_KEY)

def encrypt_text(text):
    if not text: return None
    return get_cipher().encrypt(text.encode()).decode()

def decrypt_text(encrypted_text):
    if not encrypted_text: return None
    try:
        return get_cipher().decrypt(encrypted_text.encode()).decode()
    except:
        return "[Erro na descriptografia]"
