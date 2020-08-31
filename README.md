# ipld-eth-server

[![Go Report Card](https://goreportcard.com/badge/github.com/vulcanize/ipld-eth-server)](https://goreportcard.com/report/github.com/vulcanize/ipld-eth-server)

>  ipld-eth-server is used to extract, transform, and load all eth or btc data into an IPFS-backing Postgres datastore while generating useful secondary indexes around the data in other Postgres tables

## Table of Contents
1. [Background](#background)
1. [Architecture](#architecture)
1. [Install](#install)
1. [Usage](#usage)
1. [Contributing](#contributing)
1. [License](#license)

## Background
ipld-eth-server is a collection of interfaces that are used to extract, process, store, and index
all blockchain data in Postgres-IPFS. The raw data indexed by ipld-eth-server serves as the basis for more specific watchers and applications.

Currently the service supports complete processing of all Bitcoin and Ethereum data.

## Architecture
More details on the design of ipld-eth-server can be found in [here](./documentation/architecture.md)

## Dependencies
Minimal build dependencies
* Go (1.13)
* Git
* GCC compiler
* This repository

Potential external dependencies
* Goose
* Postgres
* Statediffing go-ethereum
* Bitcoin node

## Install
1. [Goose](#goose)
1. [Postgres](#postgres)
1. [IPFS](#ipfs)
1. [Blockchain](#blockchain)
1. [Watcher](#watcher)

### Goose
[goose](https://github.com/pressly/goose) is used for migration management. While it is not necessary to use `goose` for manual setup, it
is required for running the automated tests and is used by the `make migrate` command.

### Postgres
1. [Install Postgres](https://wiki.postgresql.org/wiki/Detailed_installation_guides)
1. Create a superuser for yourself and make sure `psql --list` works without prompting for a password.
1. `createdb vulcanize_public`
1. `cd $GOPATH/src/github.com/vulcanize/ipld-eth-server`
1.  Run the migrations: `make migrate HOST_NAME=localhost NAME=vulcanize_public PORT=5432`
    - There are optional vars `USER=username:password` if the database user is not the default user `postgres` and/or a password is present
    - To rollback a single step: `make rollback NAME=vulcanize_public`
    - To rollback to a certain migration: `make rollback_to MIGRATION=n NAME=vulcanize_public`
    - To see status of migrations: `make migration_status NAME=vulcanize_public`

    * See below for configuring additional environments
    
In some cases (such as recent Ubuntu systems), it may be necessary to overcome failures of password authentication from
localhost. To allow access on Ubuntu, set localhost connections via hostname, ipv4, and ipv6 from peer/md5 to trust in: /etc/postgresql/<version>/pg_hba.conf

(It should be noted that trusted auth should only be enabled on systems without sensitive data in them: development and local test databases)

### IPFS
Data is stored in an [IPFS-backing Postgres datastore](https://github.com/ipfs/go-ds-sql).
By default data is written directly to the ipfs blockstore in Postgres; the public.blocks table.
In this case no further IPFS configuration is needed at this time.

Optionally, ipld-eth-server can be configured to function through an internal ipfs node interface using the flag: `-ipfs-mode=interface`.
Operating through the ipfs interface provides the option to configure a block exchange that can search remotely for IPLD data found missing in the local datastore.
This option is irrelevant in most cases and this mode has some disadvantages, namely:

1. Environment must have IPFS configured
1. Process will contend with the lockfile at `$IPFS_PATH`
1. Publishing and indexing of data must occur in separate db transactions

More information for configuring Postgres-IPFS can be found [here](./documentation/ipfs.md)

### Blockchain
This section describes how to setup an Ethereum or Bitcoin node to serve as a data source for ipld-eth-server

#### Ethereum
For Ethereum, [a special fork of go-ethereum](https://github.com/vulcanize/go-ethereum/tree/statediff_at_anyblock-1.9.11) is currently *requirde*.
This can be setup as follows.
Skip this step if you already have access to a node that displays the statediffing endpoints.

Begin by downloading geth and switching to the statediffing branch:

`GO111MODULE=off go get -d github.com/ethereum/go-ethereum`

`cd $GOPATH/src/github.com/ethereum/go-ethereum`

`git remote add vulcanize https://github.com/vulcanize/go-ethereum.git`

`git fetch vulcanize`

`git checkout -b statediffing vulcanize/statediff_at_anyblock-1.9.11`

Now, install this fork of geth (make sure any old versions have been uninstalled/binaries removed first):

`make geth`

And run the output binary with statediffing turned on:

`cd $GOPATH/src/github.com/ethereum/go-ethereum/build/bin`

`./geth --syncmode=full --statediff --ws`

Note: to access historical data (perform `backFill`) the node will need to operate as an archival node (`--gcmode=archive`) with rpc endpoints
exposed (`--rpc --rpcapi=eth,statediff,net`)

Warning: There is a good chance even a fully synced archive node has incomplete historical state data to some degree

The output from geth should mention that it is `Starting statediff service` and block synchronization should begin shortly thereafter.
Note that until it receives a subscriber, the statediffing process does nothing but wait for one. Once a subscription is received, this
will be indicated in the output and the node will begin processing and sending statediffs.

Also in the output will be the endpoints that will be used to interface with the node.
The default ws url is "127.0.0.1:8546" and the default http url is "127.0.0.1:8545".
These values will be used as the `ethereum.wsPath` and `ethereum.httpPath` in the config, respectively.

#### Bitcoin
For Bitcoin, ipld-eth-server is able to operate entirely through the universally exposed JSON-RPC interfaces.
This means any of the standard full nodes can be used (e.g. bitcoind, btcd) as the data source.

Point at a remote node or set one up locally using the instructions for [bitcoind](https://github.com/bitcoin/bitcoin) and [btcd](https://github.com/btcsuite/btcd).

The default http url is "127.0.0.1:8332". We will use the http endpoint as both the `bitcoin.wsPath` and `bitcoin.httpPath`
(bitcoind does not support websocket endpoints, the watcher currently uses a "subscription" wrapper around the http endpoints)

### Watcher
Finally, setup the watcher process itself.

Start by downloading ipld-eth-server and moving into the repo:

`GO111MODULE=off go get -d github.com/vulcanize/ipld-eth-server`

`cd $GOPATH/src/github.com/vulcanize/ipld-eth-server`

Then, build the binary:

`make build`

## Usage
After building the binary, run as

`./ipld-eth-server watch --config=<the name of your config file.toml>`

### Configuration

Below is the set of universal config parameters for the ipld-eth-server command, in .toml form, with the respective environmental variables commented to the side.
This set of parameters needs to be set no matter the chain type.

```toml
[database]
    name     = "vulcanize_public" # $DATABASE_NAME
    hostname = "localhost" # $DATABASE_HOSTNAME
    port     = 5432 # $DATABASE_PORT
    user     = "vdbm" # $DATABASE_USER
    password = "" # $DATABASE_PASSWORD

[watcher]
    chain = "bitcoin" # $SUPERNODE_CHAIN
    server = true # $SUPERNODE_SERVER
    ipcPath = "~/.vulcanize/vulcanize.ipc" # $SUPERNODE_IPC_PATH
    wsPath = "127.0.0.1:8082" # $SUPERNODE_WS_PATH
    httpPath = "127.0.0.1:8083" # $SUPERNODE_HTTP_PATH
    sync = true # $SUPERNODE_SYNC
    workers = 1 # $SUPERNODE_WORKERS
    backFill = true # $SUPERNODE_BACKFILL
    frequency = 45 # $SUPERNODE_FREQUENCY
    batchSize = 1 # $SUPERNODE_BATCH_SIZE
    batchNumber = 50 # $SUPERNODE_BATCH_NUMBER
    timeout = 300 # $HTTP_TIMEOUT
    validationLevel = 1 # $SUPERNODE_VALIDATION_LEVEL
```

Additional parameters need to be set depending on the specific chain.

For Bitcoin:

```toml
[bitcoin]
    wsPath  = "127.0.0.1:8332" # $BTC_WS_PATH
    httpPath = "127.0.0.1:8332" # $BTC_HTTP_PATH
    pass = "password" # $BTC_NODE_PASSWORD
    user = "username" # $BTC_NODE_USER
    nodeID = "ocd0" # $BTC_NODE_ID
    clientName = "Omnicore" # $BTC_CLIENT_NAME
    genesisBlock = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" # $BTC_GENESIS_BLOCK
    networkID = "0xD9B4BEF9" # $BTC_NETWORK_ID
```

For Ethereum:

```toml
[ethereum]
    wsPath  = "127.0.0.1:8546" # $ETH_WS_PATH
    httpPath = "127.0.0.1:8545" # $ETH_HTTP_PATH
    nodeID = "arch1" # $ETH_NODE_ID
    clientName = "Geth" # $ETH_CLIENT_NAME
    genesisBlock = "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" # $ETH_GENESIS_BLOCK
    networkID = "1" # $ETH_NETWORK_ID
    chainID = "1" # $ETH_CHAIN_ID
```

### Exposing the data
A number of different APIs for remote access to ipld-eth-server data can be exposed, these are discussed in more detail [here](./documentation/apis.md)

### Testing
`make test` will run the unit tests  
`make test` setups a clean `vulcanize_testing` db

## Contributing
Contributions are welcome!

VulcanizeDB follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/1/4/code-of-conduct).

## License
[AGPL-3.0](LICENSE) © Vulcanize Inc
