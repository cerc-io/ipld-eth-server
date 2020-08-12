## ipfs-blockchain-watcher resync
The `resync` command is made available for directing the resyncing of ipfs-blockchain-watcherdata within specified ranges.
It also contains a utility for cleaning out old data, and resetting the validation level of data.

### Rational

Manual resyncing of data can be used to re-validate data within specific ranges using a new source.

Option to remove data may be needed for bad/deprecated data or to prepare for breaking changes to the db schemas.

Resetting the validation level of data is useful for designating ranges of data for resyncing by an ongoing ipfs-blockchain-watcher
backfill process.

### Command

Usage: `./ipfs-blockchain-watcher resync --config={config.toml}`

Configuration can also be done through CLI options and/or environmental variables.
CLI options can be found using `./ipfs-blockchain-watcher resync --help`.

### Config

Below is the set of universal config parameters for the resync command, in .toml form, with the respective environmental variables commented to the side.
This set of parameters needs to be set no matter the chain type.

```toml
[database]
    name     = "vulcanize_public" # $DATABASE_NAME
    hostname = "localhost" # $DATABASE_HOSTNAME
    port     = 5432 # $DATABASE_PORT
    user     = "vdbm" # $DATABASE_USER
    password = "" # $DATABASE_PASSWORD
    
[resync]
    chain = "ethereum" # $RESYNC_CHAIN
    type = "state" # $RESYNC_TYPE
    start = 0 # $RESYNC_START
    stop = 1000 # $RESYNC_STOP
    batchSize = 10 # $RESYNC_BATCH_SIZE
    batchNumber = 100 # $RESYNC_BATCH_NUMBER
    timeout = 300 # $HTTP_TIMEOUT
    clearOldCache = true # $RESYNC_CLEAR_OLD_CACHE
    resetValidation = true # $RESYNC_RESET_VALIDATION
```

Additional parameters need to be set depending on the specific chain.

For Bitcoin: 

```toml
[bitcoin]
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
    httpPath = "127.0.0.1:8545" # $ETH_HTTP_PATH
    nodeID = "arch1" # $ETH_NODE_ID
    clientName = "Geth" # $ETH_CLIENT_NAME
    genesisBlock = "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" # $ETH_GENESIS_BLOCK
    networkID = "1" # $ETH_NETWORK_ID
```
