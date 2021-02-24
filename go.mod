module github.com/vulcanize/ipld-eth-server

go 1.13

require (
	github.com/ethereum/go-ethereum v1.9.25
	github.com/graph-gophers/graphql-go v0.0.0-20201003130358-c5bdf3b1108e
	github.com/ipfs/go-block-format v0.0.2
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-ipfs-blockstore v1.0.1
	github.com/ipfs/go-ipfs-ds-help v1.0.0
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.8.0
	github.com/multiformats/go-multihash v0.0.14
	github.com/onsi/ginkgo v1.15.0
	github.com/onsi/gomega v1.10.1
	github.com/prometheus/client_golang v1.5.1
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	github.com/vulcanize/ipld-eth-indexer v0.7.0-alpha
	github.com/vulcanize/ipfs-ethdb v0.0.2-alpha
	golang.org/x/sys v0.0.0-20210218155724-8ebf48af031b // indirect
)

replace github.com/ethereum/go-ethereum v1.9.25 => github.com/vulcanize/go-ethereum v1.9.25-statediff-0.0.14

replace github.com/vulcanize/ipfs-ethdb v0.0.2-alpha => github.com/vulcanize/pg-ipfs-ethdb v0.0.2-alpha
