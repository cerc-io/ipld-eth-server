#!/bin/sh

echo "Beginning the ipld-eth-server process"

START_CMD="./ipld-eth-server"
if [ "true" == "$CERC_REMOTE_DEBUG" ] && [ -x "/usr/local/bin/dlv" ]; then
    START_CMD="/usr/local/bin/dlv --listen=:40000 --headless=true --api-version=2 --accept-multiclient exec `pwd`/ipld-eth-server --continue --"
fi

echo running: $START_CMD ${VDB_COMMAND} --config=`pwd`/config.toml
$START_CMD ${VDB_COMMAND} --config=`pwd`/config.toml
rv=$?

if [ $rv != 0 ]; then
  echo "ipld-eth-server startup failed"
  exit 1
fi