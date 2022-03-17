set -e
set -o xtrace

export ETH_FORWARD_ETH_CALLS=true
export DB_WRITE=false
export ETH_HTTP_PATH="dapptools:8545"
export ETH_PROXY_ON_ERROR=false
export WATCHED_ADDRESS_GAP_FILLER_ENABLED=false
export WATCHED_ADDRESS_GAP_FILLER_INTERVAL=5

# Clear up existing docker images and volume.
docker-compose down --remove-orphans --volumes

# Build and start the containers.
# Note: Build only if `ipld-eth-server` or other container code is modified. Otherwise comment this line.
docker-compose -f docker-compose.test.yml -f docker-compose.yml build eth-server
docker-compose -f docker-compose.test.yml -f docker-compose.yml up -d ipld-eth-db dapptools contract eth-server

export PGPASSWORD=password
export DATABASE_USER=vdbm
export DATABASE_PORT=8077
export DATABASE_PASSWORD=password
export DATABASE_HOSTNAME=127.0.0.1

# Wait for containers to be up and execute the integration test.
while [ "$(curl -s -o /dev/null -w ''%{http_code}'' localhost:8081)" != "200" ]; do echo "waiting for ipld-eth-server..." && sleep 5; done && \
          while [ "$(curl -s -o /dev/null -w ''%{http_code}'' localhost:8545)" != "200" ]; do echo "waiting for geth-statediff..." && sleep 5; done && \
          make integrationtest
