#!/bin/sh
# Runs the db migrations and starts the watcher services

# Exit if the variable tests fail
set -e
set +x

# Check the database variables are set
# XXX set defaults, don't silently fail
#test $DATABASE_HOSTNAME
#test $DATABASE_NAME
#test $DATABASE_PORT
#test $DATABASE_USER
#test $DATABASE_PASSWORD
#test $IPFS_INIT
#VDB_COMMAND=${VDB_COMMAND:-watch}
set +e

# Construct the connection string for postgres
VDB_PG_CONNECT=postgresql://$DATABASE_USER:$DATABASE_PASSWORD@$DATABASE_HOSTNAME:$DATABASE_PORT/$DATABASE_NAME?sslmode=disable

# Run the DB migrations
echo "Connecting with: $VDB_PG_CONNECT"
echo "Running database migrations"
./goose -dir migrations/vulcanizedb postgres "$VDB_PG_CONNECT" up
rv=$?

if [ $rv != 0 ]; then
  echo "Could not run migrations. Are the database details correct?"
  exit 1
fi


echo "Beginning the ipld-eth-server process"

echo running: ./ipld-eth-server ${VDB_COMMAND} --config=config.toml
./ipld-eth-server ${VDB_COMMAND} --config=config.toml
rv=$?

if [ $rv != 0 ]; then
  echo "ipld-eth-server startup failed"
  exit 1
fi