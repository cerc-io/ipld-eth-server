# Clear up existing docker images and volume.
docker-compose down --remove-orphans --volumes

docker-compose -f docker-compose.test.yml -f docker-compose.yml up -d ipld-eth-db
sleep 10
PGPASSWORD=password DATABASE_USER=vdbm DATABASE_PORT=8077 DATABASE_PASSWORD=password DATABASE_HOSTNAME=127.0.0.1 DATABASE_NAME=vulcanize_testing make test

docker-compose down --remove-orphans --volumes
