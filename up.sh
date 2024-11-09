docker compose -f logging/docker-compose.yml up -d
docker compose -f database/docker-compose.yml up -d
docker compose -f app-backend/docker-compose.yml up -d
docker compose -f weather-service/docker-compose.yml up -d
docker compose -f haproxy-ingress/docker-compose.yml up -d
