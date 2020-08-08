## ipfs-blockchain-watcher APIs
We can expose a number of different APIs for remote access to ipfs-blockchain-watcher data


### Table of Contents
1. [Postgraphile](#postgraphile)
1. [RPC Subscription Interface](#rpc-subscription-interface)
1. [Native API Recapitulation](#native-api-recapitulation)


### Postgraphile
ipfs-blockchain-watcher stores all processed data in Postgres using PG-IPFS, this includes all of the IPLD objects.
[Postgraphile](https://www.graphile.org/postgraphile/) can be used to expose GraphQL endpoints for the Postgres tables.

e.g. 

`postgraphile --plugins @graphile/pg-pubsub --subscriptions --simple-subscriptions -c postgres://localhost:5432/vulcanize_public?sslmode=disable -s public,btc,eth -a -j`


This will stand up a Postgraphile server on the public, eth, and btc schemas- exposing GraphQL endpoints for all of the tables contained under those schemas.
All of their data can then be queried with standard [GraphQL](https://graphql.org) queries.


### RPC Subscription Interface
A direct, real-time subscription to the data being processed by ipfs-blockchain-watcher can be established over WS or IPC through the [Stream](../pkg/watch/api.go#L53) RPC method.
This method is not chain-specific and each chain-type supports it, it is accessed under the "vdb" namespace rather than a chain-specific namespace. An interface for
subscribing to this endpoint is provided [here](../pkg/client/client.go).

When subscribing to this endpoint, the subscriber provides a set of RLP-encoded subscription parameters. These parameters will be chain-specific, and are used
by ipfs-blockchain-watcher to filter and return a requested subset of chain data to the subscriber. (e.g. [BTC](../pkg/btc/subscription_config.go), [ETH](../../pkg/eth/subscription_config.go)).

#### Ethereum RPC Subscription
An example of how to subscribe to a real-time Ethereum data feed from ipfs-blockchain-watcher using the `Stream` RPC method is provided below

```go
    package main 

    import (
    	"github.com/ethereum/go-ethereum/rlp"
    	"github.com/ethereum/go-ethereum/rpc"
    	"github.com/spf13/viper"
    	
        "github.com/vulcanize/ipfs-blockchain-watcher/pkg/client"
        "github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth"
        "github.com/vulcanize/ipfs-blockchain-watcher/pkg/watch"
    )

    config, _ := eth.NewEthSubscriptionConfig()
    rlpConfig, _ := rlp.EncodeToBytes(config)
    vulcPath := viper.GetString("watcher.ethSubscription.path")
    rpcClient, _ := rpc.Dial(vulcPath)
    subClient := client.NewClient(rpcClient)
    payloadChan := make(chan watch.SubscriptionPayload, 20000)
    subscription, _ := subClient.Stream(payloadChan, rlpConfig)
    for {
        select {
        case payload := <- payloadChan:
            // do something with the subscription payload
        case err := <- subscription.Err():
            // do something with the subscription error
        }
    }
```

The .toml file being used to fill the Ethereum subscription config would look something like this:

```toml
[watcher]
    [watcher.ethSubscription]
        historicalData = false
        historicalDataOnly = false
        startingBlock = 0
        endingBlock = 0
        wsPath = "ws://127.0.0.1:8080"
        [watcher.ethSubscription.headerFilter]
            off = false
            uncles = false
        [watcher.ethSubscription.txFilter]
            off = false
            src = []
            dst = []
        [watcher.ethSubscription.receiptFilter]
            off = false
            contracts = []
            topic0s = []
            topic1s = []
            topic2s = []
            topic3s = []
        [watcher.ethSubscription.stateFilter]
            off = false
            addresses = []
           intermediateNodes = false
        [watcher.ethSubscription.storageFilter]
            off = true
            addresses = []
            storageKeys = []
            intermediateNodes = false
```

These configuration parameters are broken down as follows:

`ethSubscription.wsPath` is used to define the watcher ws url OR ipc endpoint to subscribe to

`ethSubscription.historicalData` specifies whether or not ipfs-blockchain-watcher should look up historical data in its cache and
send that to the subscriber, if this is set to `false` then only newly synced/incoming data is streamed

`ethSubscription.historicalDataOnly` will tell ipfs-blockchain-watcher to only send historical data with the specified range and
not stream forward syncing data

`ethSubscription.startingBlock` is the starting block number for the range to receive data in

`ethSubscription.endingBlock` is the ending block number for the range to receive data in;
setting to 0 means the process will continue streaming indefinitely.

`ethSubscription.headerFilter` has two sub-options: `off` and `uncles`. 

- Setting `off` to true tells ipfs-blockchain-watcher to not send any headers to the subscriber
- setting `uncles` to true tells ipfs-blockchain-watcher to send uncles in addition to normal headers.

`ethSubscription.txFilter` has three sub-options: `off`, `src`, and `dst`. 

- Setting `off` to true tells ipfs-blockchain-watcher to not send any transactions to the subscriber
- `src` and `dst` are string arrays which can be filled with ETH addresses to filter transactions for,
if they have any addresses then ipfs-blockchain-watcher will only send transactions that were sent or received by the addresses contained
in `src` and `dst`, respectively.

`ethSubscription.receiptFilter` has four sub-options: `off`, `topics`, `contracts` and `matchTxs`. 

- Setting `off` to true tells ipfs-blockchain-watcher to not send any receipts to the subscriber
- `topic0s` is a string array which can be filled with event topics to filter for,
if it has any topics then ipfs-blockchain-watcher will only send receipts that contain logs which have that topic0.
- `contracts` is a string array which can be filled with contract addresses to filter for, if it contains any contract addresses the watcher will
only send receipts that correspond to one of those contracts. 
- `matchTrxs` is a bool which when set to true any receipts that correspond to filtered for transactions will be sent by the watcher, regardless of whether or not the receipt satisfies the `topics` or `contracts` filters.

`ethSubscription.stateFilter` has three sub-options: `off`, `addresses`, and `intermediateNodes`. 

- Setting `off` to true tells ipfs-blockchain-watcher to not send any state data to the subscriber
- `addresses` is a string array which can be filled with ETH addresses to filter state for,
if it has any addresses then ipfs-blockchain-watcher will only send state leafs (accounts) corresponding to those account addresses. 
- By default ipfs-blockchain-watcher only sends along state leafs, to receive branch and extension nodes as well `intermediateNodes` can be set to `true`.

`ethSubscription.storageFilter` has four sub-options: `off`, `addresses`, `storageKeys`, and `intermediateNodes`. 

- Setting `off` to true tells ipfs-blockchain-watcher to not send any storage data to the subscriber
- `addresses` is a string array which can be filled with ETH addresses to filter storage for,
if it has any addresses then ipfs-blockchain-watcher will only send storage nodes from the storage tries at those state addresses.
- `storageKeys` is another string array that can be filled with storage keys to filter storage data for. It is important to note that the storage keys need to be the actual keccak256 hashes, whereas
the addresses in the `addresses` fields are pre-hashed ETH addresses.
- By default ipfs-blockchain-watcher only sends along storage leafs, to receive branch and extension nodes as well `intermediateNodes` can be set to `true`.

### Bitcoin RPC Subscription:
An example of how to subscribe to a real-time Bitcoin data feed from ipfs-blockchain-watcher using the `Stream` RPC method is provided below

```go
    package main 

    import (
    	"github.com/ethereum/go-ethereum/rlp"
    	"github.com/ethereum/go-ethereum/rpc"
    	"github.com/spf13/viper"
    	
    	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/btc"
    	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/client"
    	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/watch"
    )

    config, _ := btc.NewBtcSubscriptionConfig()
    rlpConfig, _ := rlp.EncodeToBytes(config)
    vulcPath := viper.GetString("watcher.btcSubscription.path")
    rpcClient, _ := rpc.Dial(vulcPath)
    subClient := client.NewClient(rpcClient)
    payloadChan := make(chan watch.SubscriptionPayload, 20000)
    subscription, _ := subClient.Stream(payloadChan, rlpConfig)
    for {
        select {
        case payload := <- payloadChan:
            // do something with the subscription payload
        case err := <- subscription.Err():
            // do something with the subscription error
        }
    }
```

The .toml file being used to fill the Bitcoin subscription config would look something like this:

```toml
[watcher]
    [watcher.btcSubscription]
        historicalData = false
        historicalDataOnly = false
        startingBlock = 0
        endingBlock = 0
        wsPath = "ws://127.0.0.1:8080"
        [watcher.btcSubscription.headerFilter]
            off = false
        [watcher.btcSubscription.txFilter]
            off = false
            segwit = false
            witnessHashes = []
            indexes = []
            pkScriptClass = []
            multiSig = false
            addresses = []
```

These configuration parameters are broken down as follows:

`btcSubscription.wsPath` is used to define the ipfs-blockchain-watcher ws url OR ipc endpoint to subscribe to

`btcSubscription.historicalData` specifies whether or not ipfs-blockchain-watcher should look up historical data in its cache and
send that to the subscriber, if this is set to `false` then ipfs-blockchain-watcher only streams newly synced/incoming data

`btcSubscription.historicalDataOnly` will tell ipfs-blockchain-watcher to only send historical data with the specified range and
not stream forward syncing data

`btcSubscription.startingBlock` is the starting block number for the range to receive data in

`btcSubscription.endingBlock` is the ending block number for the range to receive data in;
setting to 0 means the process will continue streaming indefinitely.

`btcSubscription.headerFilter` has one sub-option: `off`. 

- Setting `off` to true tells ipfs-blockchain-watcher to
not send any headers to the subscriber.
- Additional header-filtering options will be added in the future.

`btcSubscription.txFilter` has seven sub-options: `off`, `segwit`, `witnessHashes`, `indexes`, `pkScriptClass`, `multiSig`, and `addresses`.

- Setting `off` to true tells ipfs-blockchain-watcher to not send any transactions to the subscriber.
- Setting `segwit` to true tells ipfs-blockchain-watcher to only send segwit transactions.
- `witnessHashes` is a string array that can be filled with witness hash string; if it contains any hashes ipfs-blockchain-watcher will only send transactions that contain one of those hashes.
- `indexes` is an int64 array that can be filled with tx index numbers; if it contains any integers ipfs-blockchain-watcher will only send transactions at those indexes (e.g. `[0]` will send only coinbase transactions)
- `pkScriptClass` is an uint8 array that can be filled with pk script class numbers; if it contains any integers ipfs-blockchain-watcher will only send transactions that have at least one tx output with one of the specified pkscript classes;
possible class types are 0 through 8 as defined [here](https://github.com/btcsuite/btcd/blob/master/txscript/standard.go#L52).
- Setting `multisig` to true tells ipfs-blockchain-watcher to send only multi-sig transactions- to send only transaction that have at least one tx output that requires more than one signature to spend.
- `addresses` is a string array that can be filled with btc address strings; if it contains any addresses ipfs-blockchain-watcher will only send transactions that have at least one tx output with at least one of the provided addresses.


### Native API Recapitulation:
In addition to providing novel Postgraphile and RPC-Subscription endpoints, we are working towards complete recapitulation of the
standard chain APIs. This will allow direct compatibility with software that already makes use of the standard interfaces.

#### Ethereum JSON-RPC API
ipfs-blockchain-watcher currently faithfully recapitulates portions of the Ethereum JSON-RPC api standard.

The currently supported endpoints include:  
`eth_blockNumber`  
`eth_getLogs`  
`eth_getHeaderByNumber`  
`eth_getBlockByNumber`  
`eth_getBlockByHash`  
`eth_getTransactionByHash`  

Additional endpoints will be added in the near future, with the immediate goal of recapitulating the largest set of "eth_" endpoints which can be provided as a service.

#### Bitcoin JSON-RPC API:
In the near future, the standard Bitcoin JSON-RPC interfaces will be implemented.
