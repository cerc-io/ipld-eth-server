#!/bin/sh

START_CMD="./ipld-eth-server"
if [ "true" == "$CERC_REMOTE_DEBUG" ] && [ -x "/usr/local/bin/dlv" ]; then
    START_CMD="/usr/local/bin/dlv --listen=:40000 --headless=true --api-version=2 --accept-multiclient exec `pwd`/ipld-eth-server --continue --"
fi

exec $START_CMD ${VDB_COMMAND:-serve}
