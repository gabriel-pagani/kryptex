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