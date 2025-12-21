# Kryptex
Portal de gerenciamento de senhas local

## Instalação e Configuração Inicial

#### 1. Clone o repositório:
```
git clone https://github.com/gabriel-pagani/kryptex.git && cd kryptex/
```

#### 2. Configure as variáveis de ambiente:
Crie um arquivo .env na raiz do projeto (baseado no [.env.example](https://github.com/gabriel-pagani/kryptex/blob/main/.env.example)) e configure as credenciais.
```
cp --update=none .env.example .env
```

```bash
# Conteúdo do .env após a cópia
SECRET_KEY="CHANGE-ME"
DEBUG="0"
ALLOWED_HOSTS="localhost"
CSRF_TRUSTED_ORIGINS="https://localhost"
```

#### 3. Build e Start inicial:
Execute o comando abaixo para gerar certificados seguros.
```
make generate-certs
```

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
