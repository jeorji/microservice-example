docker compose -f haproxy-ingress/docker-compose.yml down
docker compose -f weather-service/docker-compose.yml down
docker compose -f app-backend/docker-compose.yml down
docker compose -f database/docker-compose.yml down
docker compose -f logging/docker-compose.yml down
