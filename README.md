# Kryptex
Portal de gerenciamento de senhas local

## Instalação e Configuração Inicial

#### 1. Clone o repositório:
```
git clone https://github.com/gabriel-pagani/kryptex.git && cd kryptex/
```

#### 2. Configure as variáveis de ambiente:
Crie um arquivo local_settings.py na pasta [project](https://github.com/gabriel-pagani/kryptex/tree/main/project) (baseado no [local_settings.example.py](https://github.com/gabriel-pagani/kryptex/blob/main/project/local_settings.example.py)) e configure as credenciais.
```
cp --update=none local_settings.example.py local_settings.py
```

```bash
# Conteúdo do local_settings.py após a cópia
SECRET_KEY = 'CHANGE-ME'

DEBUG = True

ALLOWED_HOSTS = [
    '127.0.0.1',
]

CSRF_TRUSTED_ORIGINS = [
    'https://127.0.0.1:8000',
    'http://127.0.0.1:8000',
]

ENCRYPTION_KEY = 'CHANGE-ME'
```
Comando para gerar uma ENCRYPTION_KEY válida.
```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

#### 3. Build e Start inicial:
Execute o comando de build para buildar e subir o container.
```
make build-system
```
Para acessar o sistema, crie um super usuário.
```bash
make create-superuser

# Login padrão
Usuário: admin
Senha: 1234
```

# Licença
See the [LICENSE](https://github.com/gabriel-pagani/kryptex/blob/main/LICENSE) file for more details.

# Informação para Contato
Email: gabrielpaganidesouza@gmail.com
