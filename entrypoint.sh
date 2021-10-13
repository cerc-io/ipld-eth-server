#!/bin/sh

echo "Beginning the ipld-eth-server process"

echo running: ./ipld-eth-server ${VDB_COMMAND} --config=config.toml
./ipld-eth-server ${VDB_COMMAND} --config=config.toml
rv=$?

if [ $rv != 0 ]; then
  echo "ipld-eth-server startup failed"
  exit 1
fi