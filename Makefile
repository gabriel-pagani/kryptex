build-system:
	@docker compose down && docker compose build --no-cache && docker compose up -d

start-system:
	@docker compose up -d

stop-system:
	@docker compose down

restart-system:
	@docker compose down && docker compose up -d

generate-certs:
	@mkdir certs && cd certs && mkcert -key-file key.pem -cert-file cert.pem localhost && cd ..

create-superuser:
	@docker compose exec app python manage.py shell -c "from django.contrib.auth.models import User; User.objects.filter(username='admin').exists() or User.objects.create_superuser(username='admin', password='1234')"

backup-database:
	@rm -rf backup && mkdir backup
	@echo "Criando backup criptografado do banco de dados..."
	@echo "=================================================="
	@openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 -in database/db.sqlite3 -out backup/kryptex_$(shell date +%d%m%y_%H%M%S).db.enc
	@echo "==================================================";
	@echo "Backup criado! kryptex_$(shell date +%d%m%y_%H%M%S).db.enc";

restore-backup:
	@echo "Recuperando backup criptografado do banco de dados..."
	@echo "====================================================================="
	@openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in backup/*.db.enc -out database/backup.sqlite3
	@echo "====================================================================="
	@echo "Backup recuperado!";

container-terminal:
	@docker compose exec app sh

container-logs:
	@docker compose logs -f

list-images:
	@docker images

list-volumes:
	@docker volume ls

list-containers:
	@docker ps -a