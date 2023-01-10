#!/bin/bash

# Remove any existing containers / volumes
docker-compose down --remove-orphans --volumes

# Spin up DB and run migrations
docker-compose up -d migrations ipld-eth-db
sleep 30

# Run unit tests
go clean -testcache
PGPASSWORD=password DATABASE_USER=vdbm DATABASE_PORT=8077 DATABASE_PASSWORD=password DATABASE_HOSTNAME=127.0.0.1 DATABASE_NAME=vulcanize_testing make test

# Clean up
docker-compose down --remove-orphans --volumes
rm -rf out/
