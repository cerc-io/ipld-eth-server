#!/bin/bash

set -e

# Set up repo
start_dir=$(pwd)
temp_dir=$(mktemp -d)
cd $temp_dir
git clone -b $(cat /tmp/git_head_ref) "https://github.com/$(cat /tmp/git_repository).git"
cd ipld-eth-server

## Remove the branch and github related info. This way future runs wont be confused.
#rm -f /tmp/git_head_ref /tmp/git_repository

# Setup the DB
cd $temp_dir
git clone "https://github.com/vulcanize/ipld-eth-db.git"; cd ipld-eth-db; git checkout $(cat /tmp/ipld_eth_db_ref)

# Spin Up DB using Stack Orchestrator
cd $temp_dir
git clone "https://github.com/vulcanize/stack-orchestrator.git"; cd stack-orchestrator; git checkout $(cat /tmp/stack_orchestrator_ref)

cd ${temp_dir}/stack-orchestrator
echo vulcanize_ipld_eth_db=${temp_dir}/ipld-eth-db > ./config.sh

## Remove existing containers if they are present
docker-compose -f docker/local/docker-compose-db-sharding.yml --env-file ./config.sh down -v --remove-orphans;

trap 'cd ${temp_dir}/stack-orchestrator; docker-compose -f docker/local/docker-compose-db-sharding.yml --env-file ./config.sh down -v --remove-orphans; ' SIGINT SIGTERM
docker-compose -f docker/local/docker-compose-db-sharding.yml --env-file ./config.sh up -d

# Remove old logs so there's no confusion, then run test
rm -f /tmp/test.log /tmp/return_test.txt
cd ${temp_dir}/ipld-eth-server
PGPASSWORD=password DATABASE_USER=vdbm DATABASE_PORT=8077 DATABASE_PASSWORD=password DATABASE_HOSTNAME=localhost DATABASE_NAME=vulcanize_testing make test >  /tmp/test.log
echo $? > /tmp/return_test.txt

# Clean up

cd ${temp_dir}/stack-orchestrator; docker-compose -f docker/local/docker-compose-db-sharding.yml --env-file ./config.sh down -v --remove-orphans
cd $start_dir
rm -fr $temp_dir
