# Kryptex

Comando para gerar a ENCRYPTION_KEY
```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```