#!/bin/bash

set -e

# Set up repo
start_dir=$(pwd)
temp_dir=$(mktemp -d)
cd $temp_dir
git clone -b $(cat /tmp/git_head_ref) "https://github.com/$(cat /tmp/git_repository).git"
cd ipld-eth-server

## Remove the branch and github related info. This way future runs wont be confused.
rm -f /tmp/git_head_ref /tmp/git_repository

# Spin up DB
docker-compose -f docker-compose.yml up -d ipld-eth-db
trap "docker-compose down --remove-orphans; cd $start_dir ; rm -r $temp_dir" SIGINT SIGTERM ERR
sleep 10

# Remove old logs so there's no confusion, then run test
rm -f /tmp/test.log /tmp/return_test.txt
PGPASSWORD=password DATABASE_USER=vdbm DATABASE_PORT=8077 DATABASE_PASSWORD=password DATABASE_HOSTNAME=127.0.0.1 DATABASE_NAME=vulcanize_testing make test >  /tmp/test.log
echo $? > /tmp/return_test.txt

# Clean up
docker-compose -f docker-compose.yml down -v --remove-orphans
cd $start_dir
rm -fr $temp_dir

