build-system:
	@if [ "$(scope)" = "front" ] || [ -z "$(scope)" ]; then \
		cd frontend/ && npm install && npm run build; \
	fi

	@if [ "$(scope)" = "back" ] || [ -z "$(scope)" ]; then \
		cd _deploy/ && docker compose up -d --build; \
	fi

clean-system:
	@cd _deploy/ && \
	docker compose down -v && \
	docker system prune -a --volumes --force && \
    cd .. && rm -rf backend/build/ backend/static/ database/ frontend/node_modules/

start-system:
	@cd _deploy/ && \
	docker compose up -d

stop-system:
	@cd _deploy/ && \
	docker compose down

restart-system:
	@cd _deploy/ && \
	docker compose down && \
	docker compose up -d

create-superuser:
	@cd _deploy/ && \
	docker compose exec app python manage.py shell -c "from app.models import Users; Users.objects.filter(username='admin').exists() or Users.objects.create_superuser(username='admin', password='1234')"

container-terminal:
	@cd _deploy/ && \
	docker compose exec $(container) sh

containers-logs:
	@cd _deploy/ && \
	docker compose logs -f $(container)

list-images:
	@docker images

list-volumes:
	@docker volume ls

list-containers:
	@docker ps -a
