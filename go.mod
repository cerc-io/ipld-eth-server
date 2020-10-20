module github.com/vulcanize/ipld-eth-server

go 1.13

require (
	github.com/ethereum/go-ethereum v1.9.11
	github.com/ipfs/go-block-format v0.0.2
	github.com/ipfs/go-cid v0.0.5
	github.com/ipfs/go-ipfs-blockstore v1.0.0
	github.com/ipfs/go-ipfs-ds-help v1.0.0
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.5.2
	github.com/multiformats/go-multihash v0.0.13
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.1
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	github.com/vulcanize/ipld-eth-indexer v0.4.0-alpha
	github.com/vulcanize/pg-ipfs-ethdb v0.0.1-alpha
)

replace github.com/ethereum/go-ethereum v1.9.11 => /Users/iannorden/go/src/github.com/ethereum/go-ethereum

replace github.com/vulcanize/ipld-eth-indexer v0.4.0-alpha => /Users/iannorden/go/src/github.com/vulcanize/ipld-eth-indexer
