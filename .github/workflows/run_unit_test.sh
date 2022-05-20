#!/bin/bash

set -e

# Set up repo
start_dir=$(pwd)
temp_dir=$(mktemp -d)
cd $temp_dir
git clone -b $(cat /tmp/git_head_ref) "https://github.com/$(cat /tmp/git_repository).git"
cd ipld-eth-server
mkdir -p out

## Remove the branch and github related info. This way future runs wont be confused.
rm -f /tmp/git_head_ref /tmp/git_repository

# Remove existing docker-tsdb directory
rm -rf out/docker-tsdb/

# Copy over files to setup TimescaleDB
ID=$(docker create vulcanize/ipld-eth-db:v4.1.1-alpha)
docker cp $ID:/app/docker-tsdb out/docker-tsdb/
docker rm -v $ID

# Spin up TimescaleDB
docker-compose -f out/docker-tsdb/docker-compose.test.yml -f docker-compose.yml up ipld-eth-db
trap "docker-compose -f out/docker-tsdb/docker-compose.test.yml -f docker-compose.yml down --remove-orphans --volumes; cd $start_dir ; rm -r $temp_dir" SIGINT SIGTERM ERR
sleep 45

# Remove old logs so there's no confusion, then run test
rm -f /tmp/test.log /tmp/return_test.txt
PGPASSWORD=password DATABASE_USER=vdbm DATABASE_PORT=8066 DATABASE_PASSWORD=password DATABASE_HOSTNAME=127.0.0.1 DATABASE_NAME=vulcanize_testing_v4 make test >  /tmp/test.log
echo $? > /tmp/return_test.txt

# Clean up
docker-compose -f out/docker-tsdb/docker-compose.test.yml -f docker-compose.yml down --remove-orphans --volumes
cd $start_dir
rm -fr $temp_dir
