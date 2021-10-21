module github.com/vulcanize/ipld-eth-server

go 1.13

require (
	github.com/ethereum/go-ethereum v1.10.11
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/graph-gophers/graphql-go v0.0.0-20201113091052-beb923fada29
	github.com/ipfs/go-block-format v0.0.3
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-ipfs-blockstore v1.0.1
	github.com/ipfs/go-ipfs-ds-help v1.0.0
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.10.2
	github.com/machinebox/graphql v0.2.2
	github.com/mailgun/groupcache/v2 v2.2.1
	github.com/matryer/is v1.4.0 // indirect
	github.com/multiformats/go-multihash v0.0.15
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/prometheus/client_golang v1.11.0
	github.com/shirou/gopsutil v3.21.5+incompatible // indirect
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	github.com/tklauser/go-sysconf v0.3.6 // indirect
	github.com/vulcanize/eth-ipfs-state-validator v0.0.2
	github.com/vulcanize/gap-filler v0.3.1
	github.com/vulcanize/ipfs-ethdb v0.0.5
	golang.org/x/sys v0.0.0-20211007075335-d3039528d8ac // indirect
	golang.org/x/tools v0.1.7 // indirect
)

replace github.com/ethereum/go-ethereum v1.10.11 => github.com/vulcanize/go-ethereum v1.10.11-statediff-0.0.27
