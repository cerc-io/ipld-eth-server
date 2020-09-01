# ipld-eth-server

[![Go Report Card](https://goreportcard.com/badge/github.com/vulcanize/ipld-eth-server)](https://goreportcard.com/report/github.com/vulcanize/ipld-eth-server)

>  ipld-eth-server is the server backend for indexed ETH IPLD objects

## Table of Contents
1. [Background](#background)
1. [Install](#install)
1. [Usage](#usage)
1. [Contributing](#contributing)
1. [License](#license)

## Background
NOTE: WIP

ipld-eth-server is used to service queries against the indexed Ethereum IPLD objects indexed by [ipld-eth-indexer](https://github.com/vulcanize/ipld-eth-indexer).

It exposes standard Ethereum JSON RPC endpoints on top of the database, in some cases these endpoints can leverage the unique indexes to improve query performance.
Additional, unique endpoints are exposed which utilize the new indexes and state diff data objects.


## Dependencies
Minimal build dependencies
* Go (1.13)
* Git
* GCC compiler
* This repository

External dependency
* Postgres database populated by [ipld-eth-indexer](https://github.com/vulcanize/ipld-eth-indexer)

## Install
Start by downloading ipld-eth-server and moving into the repo:

`GO111MODULE=off go get -d github.com/vulcanize/ipld-eth-server`

`cd $GOPATH/src/github.com/vulcanize/ipld-eth-server`

Then, build the binary:

`make build`

## Usage
After building the binary, run as

`./ipld-eth-server serve --config=<the name of your config file.toml>`

### Configuration

Below is the set of parameters for the ipld-eth-server command, in .toml form, with the respective environmental variables commented to the side.
The corresponding CLI flags can be found with the `./ipld-eth-server serve --help` command.

```toml
[database]
    name     = "vulcanize_public" # $DATABASE_NAME
    hostname = "localhost" # $DATABASE_HOSTNAME
    port     = 5432 # $DATABASE_PORT
    user     = "postgres" # $DATABASE_USER
    password = "" # $DATABASE_PASSWORD

[log]
    level = "info" # $LOGRUS_LEVEL

[server]
    ipcPath = "~/.vulcanize/vulcanize.ipc" # $SERVER_IPC_PATH
    wsPath = "127.0.0.1:8081" # $SERVER_WS_PATH
    httpPath = "127.0.0.1:8082" # $SERVER_HTTP_PATH
```

The `database` fields are for connecting to a Postgres database that has been/is being populated by [ipld-eth-indexer](https://github.com/vulcanize/ipld-eth-indexer).
The `server` fields set the paths for exposing the ipld-eth-server endpoints


### Endpoints
#### IPLD subscription
TODO: Port the IPLD RPC subscription endpoints after the decoupling

#### Ethereum JSON-RPC
ipld-eth-server currently recapitulates portions of the Ethereum JSON-RPC api standard.

The currently supported standard endpoints are:
`eth_blockNumber`
`eth_getLogs`
`eth_getHeaderByNumber`
`eth_getBlockByNumber`
`eth_getBlockByHash`
`eth_getTransactionByHash`

TODO: Add the rest of the standard endpoints add unique endpoints (e.g. getSlice)

### Testing
`make test` will run the unit tests  
`make test` setups a clean `vulcanize_testing` db

## Contributing
Contributions are welcome!

VulcanizeDB follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/1/4/code-of-conduct).

## License
[AGPL-3.0](LICENSE) © Vulcanize Inc
