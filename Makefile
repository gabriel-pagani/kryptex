build-system:
	docker compose up -d --build

start-system:
	docker compose up -d

stop-system:
	docker compose down

restart-system:
	docker compose down && docker compose up -d

container-terminal:
	docker compose exec app sh

container-logs:
	docker compose logs -f

list-images:
	docker images

list-volumes:
	docker volume ls

list-containers:
	docker ps -a