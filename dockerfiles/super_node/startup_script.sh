#!/bin/sh
# Runs the db migrations and starts the watcher services

# Exit if the variable tests fail
set -e
set +x

# Check the database variables are set
test $DATABASE_HOSTNAME
test $DATABASE_NAME
test $DATABASE_PORT
test $DATABASE_USER
test $DATABASE_PASSWORD
test $IPFS_INIT
test $VDB_COMMAND
set +e

# Export our database variables so that the IPFS Postgres plugin can use them
export IPFS_PGHOST=$DATABASE_HOSTNAME
export IPFS_PGUSER=$DATABASE_USER
export IPFS_PGDATABASE=$DATABASE_NAME
export IPFS_PGPORT=$DATABASE_PORT
export IPFS_PGPASSWORD=$DATABASE_PASSWORD

# Construct the connection string for postgres
VDB_PG_CONNECT=postgresql://$DATABASE_USER:$DATABASE_PASSWORD@$DATABASE_HOSTNAME:$DATABASE_PORT/$DATABASE_NAME?sslmode=disable

# Run the DB migrations
echo "Connecting with: $VDB_PG_CONNECT"
echo "Running database migrations"
./goose -dir migrations/vulcanizedb postgres "$VDB_PG_CONNECT" up


# If the db migrations ran without err
if [[ $? -eq 0 ]]; then
    # and IPFS_INIT is true
    if [[ "$IPFS_INIT" = true ]] ; then
        # initialize PG-IPFS
        echo "Initializing Postgres-IPFS profile"
        ./ipfs init --profile=postgresds
    else
        echo "IPFS profile already initialized, skipping initialization"
    fi
else
    echo "Could not run migrations. Are the database details correct?"
    exit 1
fi

# If IPFS initialization was successful
if [[ $? -eq 0 ]]; then
    echo "Running the VulcanizeDB process"
    ./ipfs-blockchain-watcher ${VDB_COMMAND} --config=config.toml
else
    echo "Could not initialize IPFS."
    exit 1
fi

# If VulcanizeDB process was successful
if [ $? -eq 0 ]; then
    echo "VulcanizeDB process ran successfully"
else
    echo "Could not start VulcanizeDB process. Is the config file correct?"
    exit 1
fi